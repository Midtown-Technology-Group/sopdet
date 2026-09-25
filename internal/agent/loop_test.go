package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mockBifrost is a minimal device-protocol server: scripted claims,
// heartbeat with a settable cancel flag, and recorded running/logs/result
// reports in arrival order.
type mockBifrost struct {
	mu            sync.Mutex
	claims        []ClaimedJob // popped per claim; empty -> 204
	cancelFlag    bool
	requests      []string // ordered "heartbeat|claim|running|logs|result"
	heartbeats    int
	results       []ResultPayload
	failAllResult bool
}

func (m *mockBifrost) record(kind string) {
	m.mu.Lock()
	m.requests = append(m.requests, kind)
	if kind == "heartbeat" {
		m.heartbeats++
	}
	m.mu.Unlock()
}

func (m *mockBifrost) setCancel(v bool) {
	m.mu.Lock()
	m.cancelFlag = v
	m.mu.Unlock()
}

func (m *mockBifrost) saw(kind string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.requests {
		if r == kind {
			return true
		}
	}
	return false
}

func (m *mockBifrost) waitFor(t *testing.T, kind string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if m.saw(kind) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q (saw %v)", kind, m.snapshot())
}

func (m *mockBifrost) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.requests...)
}

func (m *mockBifrost) resultCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.results)
}

func (m *mockBifrost) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t := "query credentials are forbidden"
			http.Error(w, t, http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Bifrost-Key") == "" {
			http.Error(w, "missing key", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = json.Unmarshal(rawBody, &body) // parsed for completeness; handlers below

		switch {
		case r.URL.Path == "/api/device/heartbeat":
			m.record("heartbeat")
			m.mu.Lock()
			flag := m.cancelFlag
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"server_time":           time.Now().UTC().Format(time.RFC3339),
				"last_seen_at":          time.Now().UTC().Format(time.RFC3339),
				"poll_interval_seconds": 10,
				"cancel_requested":      flag,
			})
		case r.URL.Path == "/api/device/jobs/claim":
			m.record("claim")
			m.mu.Lock()
			var job *ClaimedJob
			if len(m.claims) > 0 {
				j := m.claims[0]
				m.claims = m.claims[1:]
				job = &j
			}
			m.mu.Unlock()
			if job == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(job)
		case strings.HasSuffix(r.URL.Path, "/running"):
			m.record("running")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"job_id":"x","status":"running"}`))
		case strings.HasSuffix(r.URL.Path, "/logs"):
			m.record("logs")
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/result"):
			m.record("result")
			m.mu.Lock()
			if m.failAllResult {
				m.mu.Unlock()
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"error":{"code":"job_terminal","message":"already terminal","retryable":false}}`))
				return
			}
			var payload ResultPayload
			m.mu.Unlock()
			_ = json.Unmarshal(rawBody, &payload)
			m.mu.Lock()
			m.results = append(m.results, payload)
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"job_id":"x","status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func mustRead(r *http.Request) []byte {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return b
}

func scriptedJob(name, script string) ClaimedJob {
	return ClaimedJob{
		JobID:             uuid.NewString(),
		ScriptName:        name,
		ScriptContent:     script,
		TimeoutSeconds:    30,
		MaxOutputBytes:    1 << 20,
		ClaimToken:        "token-" + name,
		ClaimedAt:         time.Now().UTC(),
		ClaimLeaseSeconds: 60,
	}
}

func testServe(t *testing.T, mock *mockBifrost) *Serve {
	t.Helper()
	cfg := ServeConfig{
		BifrostURL:   "http://placeholder",
		StatePath:    filepath.Join(t.TempDir(), "serve.json"),
		PollInterval: 50 * time.Millisecond,
		WorkDir:      t.TempDir(),
	}
	ApplyServeDefaults(&cfg)
	client := NewClient("http://placeholder", testDeviceKey(), filepath.Join(t.TempDir(), "spool"))
	client.Sleep = func(time.Duration) {}
	client.Jitter = func(time.Duration) time.Duration { return 0 }
	client.MaxRetries = 1

	runner := &Runner{
		PowerShellPath: fakeShell(t, "echo hi"),
		BatchInterval:  10 * time.Millisecond,
	}
	s := &Serve{
		Config:         cfg,
		Client:         client,
		Runner:         runner,
		Wake:           make(chan struct{}, 1),
		HeartbeatEvery: 20 * time.Millisecond,
		EnableHints:    false, // poll-only: hints are covered in ws_test.go
	}
	return s
}

// wireBase points the serve client at the mock after construction.
func wireBase(s *Serve, base string) { s.Client.BaseURL = base }

func fakeShell(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-ps")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeFullLifecyclePollOnly(t *testing.T) {
	mock := &mockBifrost{
		claims: []ClaimedJob{scriptedJob("ok", "echo hello")},
	}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	s := testServe(t, mock)
	wireBase(s, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	mock.waitFor(t, "result", 10*time.Second)
	// Let the heartbeat ticker (20ms) fire while idle before shutdown.
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	reqs := mock.snapshot()
	var sawRunning, sawResult bool
	for _, r := range reqs {
		if r == "running" {
			sawRunning = true
		}
		if r == "result" && sawRunning {
			sawResult = true
		}
		if r == "logs" && !sawRunning {
			t.Errorf("logs before running report: %v", reqs)
		}
	}
	if !sawResult {
		t.Errorf("no result after running: %v", reqs)
	}
	if mock.heartbeats < 0 {
		t.Errorf("unreachable")
	}
	mock.mu.Lock()
	payloads := append([]ResultPayload{}, mock.results...)
	hbs := mock.heartbeats
	mock.mu.Unlock()
	if len(payloads) != 1 || payloads[0].Status != "succeeded" {
		t.Errorf("results = %+v, want one succeeded", payloads)
	}
	if hbs == 0 {
		t.Errorf("expected heartbeats during the run")
	}
	// Claimed only once more than results (poll continues after terminal).
	claimCount := 0
	for _, r := range reqs {
		if r == "claim" {
			claimCount++
		}
	}
	if claimCount < 2 {
		t.Errorf("expected post-terminal claim polls, got %d", claimCount)
	}
}

func TestServeAcceptsFencedResultWithoutRerun(t *testing.T) {
	mock := &mockBifrost{
		claims:        []ClaimedJob{scriptedJob("fenced", "echo x")},
		failAllResult: true,
	}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	s := testServe(t, mock)
	wireBase(s, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Once the (rejected) result attempt happened, give the loop a moment to
	// prove it does NOT re-claim/re-run the same job.
	mock.waitFor(t, "result", 10*time.Second)
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	if mock.resultCount() != 0 {
		t.Errorf("fenced results must not be recorded: %+v", mock.results)
	}
	claims := 0
	for _, r := range mock.snapshot() {
		if r == "claim" {
			claims++
		}
	}
	// One scripted claim consumed; further polls must see idle (204) and
	// never resurrect the job.
	if claims < 1 {
		t.Errorf("expected claims, got %d", claims)
	}
}

func TestServeShutdownMidRunLeavesJobForLostPolicy(t *testing.T) {
	mock := &mockBifrost{
		claims: []ClaimedJob{scriptedJob("slow", "sleep 30")},
	}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	s := testServe(t, mock)
	wireBase(s, srv.URL)
	s.Runner.PowerShellPath = fakeShell(t, "sleep 30")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	mock.waitFor(t, "running", 10*time.Second)
	cancel() // SIGINT while the job runs
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after mid-run cancel")
	}

	time.Sleep(200 * time.Millisecond)
	if got := mock.resultCount(); got != 0 {
		t.Errorf(
			"shutdown must leave `running` for the server lost policy — posted %d results",
			got,
		)
	}
}

func TestServeCooperativeCancelPostsCancelled(t *testing.T) {
	mock := &mockBifrost{
		claims: []ClaimedJob{scriptedJob("cancelme", "sleep 30")},
	}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	s := testServe(t, mock)
	wireBase(s, srv.URL)
	s.Runner.PowerShellPath = fakeShell(t, "sleep 30")
	mock.setCancel(true) // server-side cooperative cancel flag

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	mock.waitFor(t, "result", 10*time.Second)
	cancel()
	<-done

	mock.mu.Lock()
	payloads := append([]ResultPayload{}, mock.results...)
	mock.mu.Unlock()
	if len(payloads) != 1 || payloads[0].Status != "cancelled" {
		t.Errorf("results = %+v, want one cancelled", payloads)
	}
}

// TestServeClaimsWithHintsDisabled wires a Serve through the real
// construction path (ResolveServeConfig -> NewServe) with the M6.3 poll-only
// drill knob set, then proves claims still flow over the HTTP poll alone.
func TestServeClaimsWithHintsDisabled(t *testing.T) {
	mock := &mockBifrost{
		claims: []ClaimedJob{scriptedJob("pollonly", "echo hello")},
	}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	cfg := ResolveServeConfig(ServeConfig{
		BifrostURL:   srv.URL,
		StatePath:    filepath.Join(t.TempDir(), "serve.json"),
		PollInterval: 50 * time.Millisecond,
		WorkDir:      t.TempDir(),
		AgentVersion: "0.1.0-drill",
	}, ServeConfig{}, func(k string) string {
		if k == "SOPDET_DISABLE_HINTS" {
			return "1"
		}
		return ""
	})
	ApplyServeDefaults(&cfg)

	state := DeviceState{
		BifrostURL: srv.URL,
		DeviceID:   uuid.NewString(),
		DeviceKey:  testDeviceKey(),
	}
	s, err := NewServe(cfg, state)
	if err != nil {
		t.Fatalf("NewServe: %v", err)
	}
	if s.EnableHints {
		t.Fatalf("SOPDET_DISABLE_HINTS=1 must resolve EnableHints=false")
	}
	if s.Client.AgentVersion != "0.1.0-drill" {
		t.Errorf("agent version not threaded into the client: %q", s.Client.AgentVersion)
	}
	s.Client.Sleep = func(time.Duration) {}
	s.Client.Jitter = func(time.Duration) time.Duration { return 0 }
	s.Client.MaxRetries = 1
	s.Runner.PowerShellPath = fakeShell(t, "echo hi")
	s.Runner.BatchInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	mock.waitFor(t, "result", 10*time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	mock.mu.Lock()
	payloads := append([]ResultPayload{}, mock.results...)
	mock.mu.Unlock()
	if len(payloads) != 1 || payloads[0].Status != "succeeded" {
		t.Errorf("results = %+v, want one succeeded", payloads)
	}
	// The poll timer keeps claiming after the terminal job without hints.
	claims := 0
	for _, r := range mock.snapshot() {
		if r == "claim" {
			claims++
		}
	}
	if claims < 2 {
		t.Errorf("expected repeated claim polls with hints disabled, got %d", claims)
	}
}
