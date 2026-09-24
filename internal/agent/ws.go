package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
)

// WebSocket hint loop (M3.3 #840): the WS layer is a **lossy wakeup** only
// (M0) — HTTP claim remains the authority. This client:
//   - dials with `Authorization: Bearer <device_key>` header ONLY (never a
//     query credential — the platform closes query-key handshakes with 4001);
//   - subscribes to `device:{device_id}` (auto-granted server-side; the
//     explicit subscribe keeps reconnects self-contained);
//   - invokes onJobAvailable for every `device_job_available` hint;
//   - reconnects with exponential backoff + jitter until ctx is cancelled.
//
// When the socket is down the serve loop's timed claim poll (heartbeat's
// poll_interval_seconds) is the fallback — hint AND poll both reach claim.
const (
	wsBackoffBase = 500 * time.Millisecond
	wsBackoffCap  = 30 * time.Second
	wsJitterMax   = 500 * time.Millisecond
)

// WSHintClient maintains one hint connection with reconnects.
type WSHintClient struct {
	wsURL          string
	deviceID       string
	deviceKey      string
	onJobAvailable func()

	// Injectable for tests.
	Sleep  func(time.Duration)
	Jitter func(time.Duration) time.Duration
	Dial   func(ctx context.Context, wsURL string, header http.Header) (*websocket.Conn, error)
}

// NewWSHintClient derives the hint socket from the HTTP client's base URL
// and device key. The key must be a well-formed bfdk_ key (its UUID names
// the subscribed channel).
func NewWSHintClient(c *Client, onJobAvailable func()) (*WSHintClient, error) {
	deviceID, ok := ParseDeviceKeyID(c.DeviceKey)
	if !ok {
		return nil, fmt.Errorf("device key has unexpected format")
	}
	u, err := url.Parse(trimBase(c.BaseURL))
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("unsupported base URL scheme %q", u.Scheme)
	}
	u.Path = "/ws/connect"
	u.RawQuery = "" // freeze: no query credentials, ever
	return &WSHintClient{
		wsURL:          u.String(),
		deviceID:       deviceID,
		deviceKey:      c.DeviceKey,
		onJobAvailable: onJobAvailable,
	}, nil
}

// WSURL exposes the derived socket URL (tests assert it carries no query).
func (w *WSHintClient) WSURL() string { return w.wsURL }

// DeviceID exposes the subscribed device id (tests build the channel name).
func (w *WSHintClient) DeviceID() string { return w.deviceID }

// computeBackoff is the pure exponential step (attempt 0 = base), capped at
// wsBackoffCap, plus zero..wsJitterMax of jitter.
func computeBackoff(attempt int, jitter func(time.Duration) time.Duration) time.Duration {
	base := wsBackoffBase
	for i := 0; i < attempt && base < wsBackoffCap; i++ {
		base *= 2
	}
	if base > wsBackoffCap {
		base = wsBackoffCap
	}
	if jitter == nil {
		return base
	}
	return base + jitter(wsJitterMax)
}

// waitBackoff sleeps honouring context cancellation (shutdown must not sit
// through a full backoff). Tests inject a zero Sleep.
func (w *WSHintClient) waitBackoff(ctx context.Context, d time.Duration) error {
	if w.Sleep != nil {
		w.Sleep(d)
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (w *WSHintClient) dial(ctx context.Context) (*websocket.Conn, error) {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+w.deviceKey) // header-only, never query
	if w.Dial != nil {
		return w.Dial(ctx, w.wsURL, header)
	}
	conn, resp, err := websocket.Dial(ctx, w.wsURL, &websocket.DialOptions{
		HTTPHeader: header,
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws dial: HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	return conn, nil
}

// Run maintains the hint connection until ctx is cancelled. Reconnects use
// exponential backoff + jitter; every valid `device_job_available` hint
// triggers onJobAvailable (which should kick an HTTP claim — claims over
// HTTP are authoritative).
func (w *WSHintClient) Run(ctx context.Context) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := w.dial(ctx)
		if err != nil {
			if w.waitBackoff(ctx, computeBackoff(attempt, w.Jitter)) != nil {
				return
			}
			attempt++
			continue
		}
		attempt = 0

		w.consume(ctx, conn)
		conn.Close(websocket.StatusNormalClosure, "bye")

		if ctx.Err() != nil {
			return
		}
		// Unexpected disconnect: back off before redialing.
		if w.waitBackoff(ctx, computeBackoff(0, w.Jitter)) != nil {
			return
		}
	}
}

// consume reads until error/closure: acknowledges the connect frame, sends
// the explicit subscribe, and dispatches job hints.
func (w *WSHintClient) consume(ctx context.Context, conn *websocket.Conn) {
	subscribe, _ := json.Marshal(map[string]any{
		"type":     "subscribe",
		"channels": []string{"device:" + w.deviceID},
	})
	_ = conn.Write(ctx, websocket.MessageText, subscribe)

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var msg struct {
			Type  string `json:"type"`
			JobID string `json:"job_id"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "device_job_available":
			if w.onJobAvailable != nil {
				w.onJobAvailable()
			}
		case "error":
			// Denied subscribe or protocol error: keep reading; HTTP poll is
			// the fallback and the next reconnect retries the subscribe.
			continue
		}
	}
}
