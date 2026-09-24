package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// startHintServer accepts one hint connection per request with:
//   - no query string (frozen: query credentials are rejected platform-side),
//   - Authorization: Bearer <key> verified during the handshake,
//
// and hands each accepted conn to handler.
func startHintServer(t *testing.T, key string, handler func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("handshake must carry no query credentials, got %q", r.URL.RawQuery)
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return // rejected (bad/missing header)
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // httptest has no browser Origin
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "bye")
		handler(conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newHintClient(t *testing.T, baseURL, key string, onHint func()) *WSHintClient {
	t.Helper()
	hc := NewClient(baseURL, key, t.TempDir())
	ws, err := NewWSHintClient(hc, onHint)
	if err != nil {
		t.Fatalf("NewWSHintClient: %v", err)
	}
	return ws
}

func TestHintClientDerivesHeaderOnlyURL(t *testing.T) {
	key := testDeviceKey()
	hc := NewClient("https://bifrost.example/base/", key, t.TempDir())
	ws, err := NewWSHintClient(hc, nil)
	if err != nil {
		t.Fatalf("NewWSHintClient: %v", err)
	}
	if ws.WSURL() != "wss://bifrost.example/base/ws/connect" &&
		ws.WSURL() != "wss://bifrost.example/ws/connect" {
		t.Errorf("unexpected ws URL: %s", ws.WSURL())
	}
	if ws.WSURL()[:6] != "wss://" {
		t.Errorf("expected wss scheme, got %s", ws.WSURL())
	}
	// Frozen: never a query credential.
	for _, u := range []string{ws.WSURL()} {
		if len(u) > 0 {
			for i := 0; i < len(u); i++ {
				if u[i] == '?' {
					t.Errorf("ws URL must carry no query: %s", u)
				}
			}
		}
	}
	if ws.DeviceID() == "" {
		t.Errorf("device id not derived")
	}

	// Malformed key → construction error.
	bad := NewClient("https://bifrost.example", "not-a-key", t.TempDir())
	if _, err := NewWSHintClient(bad, nil); err == nil {
		t.Errorf("expected error for malformed device key")
	}
}

func TestComputeBackoffExponentialWithCap(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 500 * time.Millisecond},
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{10, 30 * time.Second}, // capped
	}
	for _, c := range cases {
		got := computeBackoff(c.attempt, nil)
		if got != c.want {
			t.Errorf("computeBackoff(%d) = %v, want %v", c.attempt, got, c.want)
		}
	}
	// Jitter adds on top of the base step.
	got := computeBackoff(1, func(d time.Duration) time.Duration { return d })
	if got != time.Second+wsJitterMax {
		t.Errorf("jittered backoff = %v", got)
	}
}

func TestHintLoopDeliversJobAvailableHeaderOnly(t *testing.T) {
	key := testDeviceKey()
	deviceID, _ := ParseDeviceKeyID(key)

	var (
		mu            sync.Mutex
		subscribeSeen string
	)
	hinted := make(chan struct{}, 4)

	srv := startHintServer(t, key, func(conn *websocket.Conn) {
		// First client frame: the explicit device-channel subscribe.
		_, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		var msg struct {
			Type     string   `json:"type"`
			Channels []string `json:"channels"`
		}
		_ = json.Unmarshal(data, &msg)
		mu.Lock()
		subscribeSeen = msg.Channels[0]
		mu.Unlock()

		// Lossy hint delivery.
		payload, _ := json.Marshal(map[string]string{
			"type":   "device_job_available",
			"job_id": "11111111-1111-1111-1111-111111111111",
		})
		_ = conn.Write(context.Background(), websocket.MessageText, payload)

		// Keep the connection open until the client disconnects.
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	})

	ws := newHintClient(t, srv.URL, key, func() {
		select {
		case hinted <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ws.Run(ctx)
		close(done)
	}()

	select {
	case <-hinted:
		// delivered
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for device_job_available hint")
	}
	mu.Lock()
	if subscribeSeen != "device:"+deviceID {
		t.Errorf("subscribed to %q, want device:%s", subscribeSeen, deviceID)
	}
	mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestHintLoopReconnectsAfterServerDrop(t *testing.T) {
	key := testDeviceKey()
	var accepts int32

	// Server accepts then drops immediately → client must redial with backoff.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("no query credentials allowed, got %q", r.URL.RawQuery)
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		atomic.AddInt32(&accepts, 1)
		conn.Close(websocket.StatusInternalError, "drop")
	}))
	t.Cleanup(srv.Close)

	var (
		mu     sync.Mutex
		sleeps []time.Duration
	)
	ws := newHintClient(t, srv.URL, key, nil)
	ws.Sleep = func(d time.Duration) {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ws.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&accepts) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&accepts); got < 2 {
		cancel()
		t.Fatalf("expected at least 2 dial attempts, got %d", got)
	}
	mu.Lock()
	if len(sleeps) == 0 {
		t.Errorf("expected a recorded backoff sleep between dials")
	}
	mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestHintLoopRejectsBadHeaderAndKeepsRetrying(t *testing.T) {
	// Wrong (but well-formed) key: the server rejects the handshake; the
	// loop must back off and retry, always in the Authorization header and
	// never in a query string.
	var attempts int32
	badKey := testDeviceKey() // valid format, different secret/device than the server's key
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("no query credentials allowed, got %q", r.URL.RawQuery)
		}
		atomic.AddInt32(&attempts, 1)
		if r.Header.Get("Authorization") != "Bearer "+testDeviceKey() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
	}))
	t.Cleanup(srv.Close)

	ws := newHintClient(t, srv.URL, badKey, nil)
	ws.Sleep = func(time.Duration) {}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ws.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&attempts) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if got := atomic.LoadInt32(&attempts); got < 2 {
		t.Errorf("expected rejected dials to retry, got %d attempts", got)
	}
}
