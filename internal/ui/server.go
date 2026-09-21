// Package ui serves a small, loopback-only branded progress page for a running
// scan. It binds 127.0.0.1 on a random port, gates every request behind a
// one-time token, and streams events to the browser over Server-Sent Events.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/progress"
)

//go:embed assets/index.html
var indexHTML []byte

const (
	eventBuffer = 1024
	historyMax  = 20000
)

// Options configures a Server.
type Options struct {
	Port int // 0 selects a free port
}

// Server is a local progress web UI. It implements progress.Sink.
type Server struct {
	ln    net.Listener
	http  *http.Server
	token string
	url   string

	mu      sync.Mutex
	subs    map[chan progress.Event]struct{}
	history []progress.Event
	closed  bool
}

// New starts listening on 127.0.0.1 and returns a ready server.
func New(o Options) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(o.Port))
	if err != nil {
		return nil, fmt.Errorf("ui listen: %w", err)
	}
	tok, err := randomToken()
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{
		ln:    ln,
		token: tok,
		url:   fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), tok),
		subs:  map[chan progress.Event]struct{}{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/", s.handleIndex)
	s.http = &http.Server{
		Handler:           secure(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// URL returns the tokenised page URL to open in a browser.
func (s *Server) URL() string { return s.url }

// Serve blocks serving requests until Close.
func (s *Server) Serve() { _ = s.http.Serve(s.ln) }

// Close shuts the server down and releases the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.http.Close()
}

// Emit records and fans an event out to connected browsers.
func (s *Server) Emit(e progress.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.history = append(s.history, e)
	if len(s.history) > historyMax {
		s.history = s.history[len(s.history)-historyMax:]
	}
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- e:
			default:
			}
		}
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan progress.Event, eventBuffer)
	s.mu.Lock()
	for _, e := range s.history {
		select {
		case ch <- e:
		default:
		}
	}
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()

	_, _ = w.Write([]byte("retry: 2000\n\n"))
	flusher.Flush()

	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case e := <-ch:
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			if err := enc.Encode(e); err != nil {
				return
			}
			_, _ = w.Write([]byte("\n"))
			flusher.Flush()
		}
	}
}

// WaitForViewers keeps the page served after the run finishes: it returns once
// a viewer has connected and then gone, or the maximum lifetime elapses, or ctx
// is cancelled. This keeps double-click launches useful without hanging a shell.
func (s *Server) WaitForViewers(ctx context.Context, max, idle time.Duration) {
	deadline := time.Now().Add(max)
	seen, disconnected := false, time.Time{}
	for {
		s.mu.Lock()
		live := len(s.subs)
		s.mu.Unlock()
		if live > 0 {
			seen = true
			disconnected = time.Time{}
		} else if seen {
			if disconnected.IsZero() {
				disconnected = time.Now()
			} else if time.Since(disconnected) >= idle {
				return
			}
		}
		if time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *Server) authorized(r *http.Request) bool {
	given := r.URL.Query().Get("t")
	return subtle.ConstantTimeCompare([]byte(given), []byte(s.token)) == 1
}

// OpenBrowser best-effort launches the default browser at url.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return fmt.Errorf("no display available")
		}
		return exec.Command("xdg-open", url).Start()
	}
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ui token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secure adds hardening headers to every response.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy",
			"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
