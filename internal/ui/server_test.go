package ui

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/progress"
)

func startServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Options{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	go s.Serve()
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHealthAndAuth(t *testing.T) {
	s := startServer(t)
	base := "http://" + s.ln.Addr().String()

	if code, _ := get(t, base+"/healthz"); code != http.StatusOK {
		t.Fatalf("healthz = %d", code)
	}
	if code, _ := get(t, base+"/"); code != http.StatusForbidden {
		t.Fatalf("index without token = %d, want 403", code)
	}
	if code, _ := get(t, base+"/?t=deadbeef"); code != http.StatusForbidden {
		t.Fatalf("index with bad token = %d, want 403", code)
	}
	code, body := get(t, base+"/?t="+s.token)
	if code != http.StatusOK || !strings.Contains(body, "SOPDET") {
		t.Fatalf("index with token = %d, contains SOPDET=%v", code, strings.Contains(body, "SOPDET"))
	}
	if code, _ := get(t, base+"/events?t=nope"); code != http.StatusForbidden {
		t.Fatalf("events with bad token = %d, want 403", code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := startServer(t)
	resp, err := http.Get("http://" + s.ln.Addr().String() + "/?t=" + s.token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got == "" {
		t.Error("missing CSP")
	}
}

func TestEventsReplayHistory(t *testing.T) {
	s := startServer(t)
	s.Emit(progress.Event{Kind: progress.KindPlan, Total: 3})
	s.Emit(progress.Event{Kind: progress.KindEntity, Entity: "host", Index: 1, Total: 3, OK: progress.Bool(true), Count: 1})

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.ln.Addr().String()+"/events?t="+s.token, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer resp.Body.Close()

	r := bufio.NewReader(resp.Body)
	var got strings.Builder
	for got.Len() < 512 {
		line, err := r.ReadString('\n')
		got.WriteString(line)
		if strings.Contains(got.String(), `"entity":"host"`) || err != nil {
			break
		}
	}
	out := got.String()
	if !strings.Contains(out, `"kind":"plan"`) || !strings.Contains(out, `"entity":"host"`) {
		t.Fatalf("stream did not replay history:\n%s", out)
	}
}

func TestEmitAfterCloseIsIgnored(t *testing.T) {
	s := startServer(t)
	_ = s.Close()
	s.Emit(progress.Event{Kind: progress.KindDone}) // must not panic or block
}

func TestWaitForViewersReturnsOnCancel(t *testing.T) {
	s := startServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	s.WaitForViewers(ctx, time.Minute, time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("WaitForViewers took %s after cancel", elapsed)
	}
}
