package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordedReq struct {
	Path string
	Key  string
	Body map[string]any
}

func newTestClient(spoolDir string) *Client {
	c := NewClient("http://placeholder", "bfdk-test", spoolDir)
	c.Sleep = func(time.Duration) {}
	c.Jitter = func(time.Duration) time.Duration { return 0 }
	c.MaxRetries = 2
	return c
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var m map[string]any
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("bad json body: %v", err)
		}
	}
	return m
}

func TestFullJobLifecycle(t *testing.T) {
	var reqs []recordedReq
	var claimCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := recordedReq{
			Path: r.URL.Path,
			Key:  r.Header.Get("X-Bifrost-Key"),
			Body: decodeBody(t, r),
		}
		reqs = append(reqs, rec)

		switch {
		case r.URL.Path == "/api/device/heartbeat":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"server_time":"2026-09-24T00:00:00Z","last_seen_at":"2026-09-24T00:00:00Z","poll_interval_seconds":10,"cancel_requested":true}`))
		case r.URL.Path == "/api/device/jobs/claim":
			if atomic.AddInt32(&claimCalls, 1) == 1 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"job_id": "11111111-1111-1111-1111-111111111111",
				"script_name": "probe",
				"script_content": "Write-Output hi",
				"params": {"a": "b"},
				"timeout_seconds": 60,
				"max_output_bytes": 1048576,
				"claim_token": "22222222-2222-2222-2222-222222222222",
				"claimed_at": "2026-09-24T00:00:01Z",
				"claim_lease_seconds": 60
			}`))
		case strings.HasSuffix(r.URL.Path, "/running"),
			strings.HasSuffix(r.URL.Path, "/logs"),
			strings.HasSuffix(r.URL.Path, "/result"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok": true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":{"code":"unknown_job","message":"nf","retryable":false}}`))
		}
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL
	ctx := context.Background()

	// Heartbeat: session bound, poll hint + cancel flag surfaced.
	hb, err := c.Heartbeat(ctx)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if hb.PollIntervalSeconds != 10 || !hb.CancelRequested {
		t.Errorf("heartbeat status = %+v", hb)
	}

	// Claim: idle first (nil), then a full job payload.
	idle, err := c.Claim(ctx)
	if err != nil || idle != nil {
		t.Fatalf("idle claim = %v, %v", idle, err)
	}
	job, err := c.Claim(ctx)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if job == nil || job.JobID == "" || job.ClaimToken == "" {
		t.Fatalf("claim payload = %+v", job)
	}
	if job.ClaimLeaseSeconds != 60 || job.TimeoutSeconds != 60 {
		t.Errorf("claim contract fields = %+v", job)
	}
	if job.ScriptContent != "Write-Output hi" || job.Params["a"] != "b" {
		t.Errorf("script/params = %+v", job)
	}

	// Running report -> logs -> result.
	if err := c.ReportRunning(ctx, job.JobID, job.ClaimToken); err != nil {
		t.Fatalf("report running: %v", err)
	}
	if err := c.PostLogs(ctx, job.JobID, job.ClaimToken, []LogBatchEntry{
		{Seq: 1, Stream: "stdout", Text: "line1", TS: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("post logs: %v", err)
	}
	if err := c.ReportResult(ctx, job.JobID, ResultPayload{
		ClaimToken: job.ClaimToken,
		Status:     "succeeded",
		ExitCode:   intPtr(0),
		Output:     "done",
	}); err != nil {
		t.Fatalf("report result: %v", err)
	}

	// Every request carried the device key header and the right paths.
	seen := map[string]bool{}
	for _, rec := range reqs {
		if rec.Key != "bfdk-test" {
			t.Errorf("missing X-Bifrost-Key on %s", rec.Path)
		}
		seen[rec.Path] = true
	}
	for _, want := range []string{
		"/api/device/heartbeat",
		"/api/device/jobs/claim",
		"/api/device/jobs/11111111-1111-1111-1111-111111111111/running",
		"/api/device/jobs/11111111-1111-1111-1111-111111111111/logs",
		"/api/device/jobs/11111111-1111-1111-1111-111111111111/result",
	} {
		if !seen[want] {
			t.Errorf("missing request to %s (saw %v)", want, seen)
		}
	}
}

func intPtr(i int) *int { return &i }

func TestRetryOnTransient5xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL
	err := c.PostLogs(context.Background(), "job-x", "tok", []LogBatchEntry{
		{Seq: 1, Stream: "stdout", Text: "x"},
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestFenceMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"code":"fence_violation","message":"stale","retryable":false}}`))
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL
	err := c.ReportResult(context.Background(), "job-x", ResultPayload{
		ClaimToken: "tok", Status: "succeeded",
	})
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("expected ErrFenced, got %v", err)
	}
	if !IsFenced(err) {
		t.Errorf("IsFenced should be true")
	}
	// 409 must NOT be retried (attempts would be MaxRetries+1 if it were).
	// One request is enough to assert via a counter:
	counterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCounter, 1)
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"code":"job_terminal","message":"done","retryable":false}}`))
	}))
	defer counterSrv.Close()
	atomic.StoreInt32(&postCounter, 0)
	c2 := newTestClient(t.TempDir())
	c2.BaseURL = counterSrv.URL
	if err := c2.ReportResult(context.Background(), "job-y", ResultPayload{ClaimToken: "t", Status: "failed"}); !errors.Is(err, ErrFenced) {
		t.Fatalf("expected ErrFenced for job_terminal, got %v", err)
	}
	if got := atomic.LoadInt32(&postCounter); got != 1 {
		t.Errorf("4xx retried: attempts = %d", got)
	}
}

var postCounter int32

func TestResultSpoolsOnOutageAndDrains(t *testing.T) {
	var healthy atomic.Bool
	var replayed atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		body, _ := json.Marshal(map[string]any{})
		raw := make([]byte, 4096)
		n, _ := r.Body.Read(raw)
		_ = body
		replayed.Store(string(raw[:n]))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL

	// Outage: result POST fails after retries and lands in the spool.
	err := c.ReportResult(context.Background(), "job-spool", ResultPayload{
		ClaimToken: "tok", Status: "succeeded", ExitCode: intPtr(0),
	})
	if err != nil {
		// ReportResult returns nil after a successful spool.
		t.Fatalf("expected spooled success, got %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(c.SpoolDir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("expected 1 spooled record, got %v", files)
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("spool mode = %o, want 600", perm)
	}

	// Recovery: drain posts the record and clears it.
	healthy.Store(true)
	pending, err := c.DrainSpool(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if pending != 0 {
		t.Errorf("pending after drain = %d", pending)
	}
	files, _ = filepath.Glob(filepath.Join(c.SpoolDir, "*.json"))
	if len(files) != 0 {
		t.Errorf("spool not cleared: %v", files)
	}
	if got, _ := replayed.Load().(string); !strings.Contains(got, "job-spool") && !strings.Contains(got, "succeeded") {
		// Body is the raw result payload JSON.
		if !strings.Contains(got, "claim_token") {
			t.Errorf("replayed body unexpected: %q", got)
		}
	}
}

func TestFencedDrainDropsRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"code":"job_terminal","message":"already lost","retryable":false}}`))
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL
	if err := c.Spool(&SpoolRecord{
		Kind: "result", JobID: "job-fenced", ClaimToken: "tok",
		Payload: map[string]any{"claim_token": "tok", "status": "succeeded"},
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := c.DrainSpool(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if pending != 0 {
		t.Errorf("fenced record must be dropped, pending = %d", pending)
	}
	files, _ := filepath.Glob(filepath.Join(c.SpoolDir, "*.json"))
	if len(files) != 0 {
		t.Errorf("fenced spool record not removed: %v", files)
	}
}

func TestSpoolRetentionSweep(t *testing.T) {
	c := newTestClient(t.TempDir())
	old := filepath.Join(c.SpoolDir, "logs-job-old.json")
	fresh := filepath.Join(c.SpoolDir, "logs-job-new.json")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	staleTime := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(old, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	removed, err := c.SweepSpool()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("stale spool file survived the sweep")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh spool file was removed: %v", err)
	}
}

func TestOversizedClaimResponseIsNotSilentlyTruncated(t *testing.T) {
	// A >512 KiB claim body must fail loudly: a silent truncation would
	// break decode AFTER the server already claimed the job (then `lost`).
	big := strings.Repeat("a", 600*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"job_id":"11111111-1111-1111-1111-111111111111","claim_token":"22222222-2222-2222-2222-222222222222","script_content":"`))
		w.Write([]byte(big))
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL
	_, err := c.Claim(context.Background())
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected explicit truncation error, got %v", err)
	}
}

func TestDrainsSpooledLogsBeforeTerminalResult(t *testing.T) {
	var healthy atomic.Bool
	var order []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		mu.Lock()
		if strings.HasSuffix(r.URL.Path, "/logs") {
			order = append(order, "logs")
		} else if strings.HasSuffix(r.URL.Path, "/result") {
			order = append(order, "result")
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL

	// Outage: log batch spools.
	if err := c.PostLogs(context.Background(), "job-order", "tok", []LogBatchEntry{
		{Seq: 1, Stream: "stdout", Text: "kept"},
	}); err != nil {
		t.Fatalf("expected spooled logs, got %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(c.SpoolDir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("expected spooled log record, got %v", files)
	}

	// Recovery: terminal result must arrive AFTER the drained logs.
	healthy.Store(true)
	if err := c.ReportResult(context.Background(), "job-order", ResultPayload{
		ClaimToken: "tok", Status: "succeeded",
	}); err != nil {
		t.Fatalf("report result: %v", err)
	}
	mu.Lock()
	got := append([]string{}, order...)
	mu.Unlock()
	if len(got) < 2 || got[0] != "logs" || got[len(got)-1] != "result" {
		t.Errorf("delivery order = %v, want logs before result", got)
	}
	files, _ = filepath.Glob(filepath.Join(c.SpoolDir, "*.json"))
	if len(files) != 0 {
		t.Errorf("spool not drained: %v", files)
	}
}

func TestDrainCountsEveryRetainedRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := newTestClient(t.TempDir())
	c.BaseURL = srv.URL
	for i := 1; i <= 3; i++ {
		if err := c.Spool(&SpoolRecord{
			Kind: "logs", JobID: "job-keep", ClaimToken: "tok",
			Payload: map[string]any{
				"claim_token": "tok",
				"entries":     []any{map[string]any{"seq": i, "stream": "stdout", "text": "x"}},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := c.DrainSpool(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if pending != 3 {
		t.Errorf("pending = %d, want 3 (every retained record counted)", pending)
	}
	files, _ := filepath.Glob(filepath.Join(c.SpoolDir, "*.json"))
	if len(files) != 3 {
		t.Errorf("records must survive the outage, got %d", len(files))
	}
}

func TestBackoffHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Default path: no injected Sleep, so waitBackoff selects on ctx.Done.
	// Claim is used because PostLogs/ReportResult legitimately return nil
	// after spooling a transient failure.
	c := NewClient(srv.URL, "bfdk-test", t.TempDir())
	c.MaxRetries = 3
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the first backoff must abort immediately

	start := time.Now()
	_, err := c.Claim(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("backoff ignored cancellation: took %v", elapsed)
	}
}
