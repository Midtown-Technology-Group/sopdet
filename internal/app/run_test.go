package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Midtown-Technology-Group/sopdet/internal/config"
)

func TestRunMinimalDryRunValidates(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	cfg := config.Defaults()
	cfg.Profile = "minimal"
	cfg.DryRun = true
	cfg.OutputPath = out
	cfg.StatePath = filepath.Join(dir, "state.json")

	res, err := Run(context.Background(), cfg, "test", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Envelope == nil || len(res.Envelope.Entities) == 0 {
		t.Fatal("no entities collected")
	}
	if res.Envelope.HostIdentifier.DeviceID == "" {
		t.Fatal("missing device id")
	}

	f, err := os.Open("../../schema/inventory.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("inventory.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("inventory.schema.json")
	if err != nil {
		t.Fatal(err)
	}

	g, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	instance, err := jsonschema.UnmarshalJSON(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(instance); err != nil {
		t.Fatalf("output failed schema: %v", err)
	}
}

// A Bifrost sync endpoint answers HTTP 200 even when the workflow failed.
// The delta baseline must only advance after a confirmed Success.
func TestStateAdvancesOnlyAfterConfirmedWorkflowSuccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("HOME", dir)
	var succeed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if succeed.Load() {
			_, _ = io.WriteString(w, `{"execution_id":"00000000-0000-4000-8000-000000000006","status":"Success"}`)
			return
		}
		_, _ = io.WriteString(w, `{"execution_id":"00000000-0000-4000-8000-000000000007","status":"Failed"}`)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Defaults()
	cfg.Profile = "minimal"
	cfg.Endpoint = srv.URL
	cfg.Delta = true
	cfg.MaxRetries = 1
	cfg.StatePath = filepath.Join(dir, "state.json")

	res, err := Run(context.Background(), cfg, "test", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Delivered || len(res.Unconfirmed) == 0 {
		t.Fatalf("failed workflow must not count as delivered: %+v", res)
	}
	if _, err := os.Stat(cfg.StatePath); !os.IsNotExist(err) {
		t.Fatalf("delta baseline advanced after an unconfirmed delivery (stat err=%v)", err)
	}

	succeed.Store(true)
	res, err = Run(context.Background(), cfg, "test", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Delivered {
		t.Fatalf("confirmed delivery not reported: %+v", res)
	}
	if _, err := os.Stat(cfg.StatePath); err != nil {
		t.Fatalf("delta baseline not saved after confirmed delivery: %v", err)
	}
}

// actionRecorder is an ingest endpoint that answers Success and records the
// envelope action of every chunk it receives.
type actionRecorder struct {
	mu      sync.Mutex
	actions []string
	down    atomic.Bool // answer 503 without recording, so chunks spool
	// failSnapshots answers recorded snapshot chunks with workflow status
	// Failed, so they are unconfirmed rather than spooled.
	failSnapshots atomic.Bool
}

func (a *actionRecorder) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Payload         string  `json:"payload"`
			ContentEncoding *string `json:"content_encoding"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		raw := []byte(req.Payload)
		if req.ContentEncoding != nil && *req.ContentEncoding == "gzip+base64" {
			zipped, err := base64.StdEncoding.DecodeString(req.Payload)
			if err != nil {
				t.Errorf("base64: %v", err)
				return
			}
			zr, err := gzip.NewReader(bytes.NewReader(zipped))
			if err != nil {
				t.Errorf("gzip: %v", err)
				return
			}
			if raw, err = io.ReadAll(zr); err != nil {
				t.Errorf("gunzip: %v", err)
				return
			}
		}
		var env struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Errorf("envelope: %v", err)
			return
		}
		a.mu.Lock()
		a.actions = append(a.actions, env.Action)
		a.mu.Unlock()
		if env.Action == "snapshot" && a.failSnapshots.Load() {
			_, _ = io.WriteString(w, `{"execution_id":"00000000-0000-4000-8000-000000000009","status":"Failed"}`)
			return
		}
		_, _ = io.WriteString(w, `{"execution_id":"00000000-0000-4000-8000-000000000008","status":"Success"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// last returns the action of the most recent run's chunks, requiring every
// chunk of that run to agree.
func (a *actionRecorder) last(t *testing.T, from int) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.actions) <= from {
		t.Fatal("endpoint received no chunks")
	}
	got := a.actions[from]
	for _, x := range a.actions[from:] {
		if x != got {
			t.Fatalf("mixed actions in one run: %v", a.actions[from:])
		}
	}
	return got
}

func (a *actionRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.actions)
}

func TestDeltaBaselineIsBoundToDeliveryTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("HOME", dir)
	var recA, recB actionRecorder
	srvA, srvB := recA.serve(t), recB.serve(t)

	cfg := config.Defaults()
	cfg.Profile = "minimal"
	cfg.Delta = true
	cfg.MaxRetries = 1
	cfg.StatePath = filepath.Join(dir, "state.json")

	run := func(endpoint string, dryRun bool) {
		t.Helper()
		c := cfg
		c.Endpoint = endpoint
		c.DryRun = dryRun
		if dryRun {
			c.OutputPath = filepath.Join(dir, "dry.json")
		}
		res, err := Run(context.Background(), c, "test", nil)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if !res.Delivered {
			t.Fatalf("run not delivered: %+v", res)
		}
	}
	expect := func(rec *actionRecorder, endpoint, want, why string) {
		t.Helper()
		from := rec.count()
		run(endpoint, false)
		if got := rec.last(t, from); got != want {
			t.Fatalf("%s: action %q, want %q", why, got, want)
		}
	}

	expect(&recA, srvA.URL, "snapshot", "first run")
	expect(&recA, srvA.URL, "delta", "same endpoint")
	expect(&recB, srvB.URL, "snapshot", "new endpoint has none of the old baseline")
	// Spooled chunks are scoped to the endpoint exactly as configured, so the
	// baseline is too: another spelling starts from a snapshot.
	expect(&recB, srvB.URL+"/", "snapshot", "trailing slash is a separate spool scope")

	run(srvB.URL, true)
	expect(&recB, srvB.URL, "snapshot", "a dry run delivered nothing, so its baseline is not the endpoint's")

	// State written before targets were recorded.
	st, err := os.ReadFile(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(st, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "target")
	if st, err = json.Marshal(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, st, 0o600); err != nil {
		t.Fatal(err)
	}
	expect(&recB, srvB.URL, "snapshot", "state without a target")
	expect(&recB, srvB.URL, "delta", "baseline rebuilt for this endpoint")
}

// A delta spooled under one endpoint spelling or API key must not replay after
// a newer delivery under another and leave the receiver behind the saved
// baseline. Baseline and spool share the exact endpoint and key, so the run
// that drains the stale chunk sends a snapshot after it.
func TestStaleSpoolForAnotherIdentityIsFollowedBySnapshot(t *testing.T) {
	cases := map[string]func(url string) (string, string){
		"endpoint spelling": func(url string) (string, string) { return url + "/", "synthetic-key-a" },
		"api key":           func(url string) (string, string) { return url, "synthetic-key-b" },
	}
	for name, other := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
			t.Setenv("HOME", dir)
			var rec actionRecorder
			srv := rec.serve(t)

			cfg := config.Defaults()
			cfg.Profile = "minimal"
			cfg.Delta = true
			cfg.MaxRetries = 1
			cfg.StatePath = filepath.Join(dir, "state.json")
			run := func(endpoint, key string) Result {
				t.Helper()
				c := cfg
				c.Endpoint = endpoint
				c.APIKey = key
				res, err := Run(context.Background(), c, "test", nil)
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				return res
			}

			if !run(srv.URL, "synthetic-key-a").Delivered {
				t.Fatal("baseline run not delivered")
			}
			rec.down.Store(true)
			if res := run(srv.URL, "synthetic-key-a"); res.Delivered || res.Spooled == 0 {
				t.Fatalf("outage did not spool: %+v", res)
			}
			rec.down.Store(false)
			if !run(other(srv.URL)).Delivered {
				t.Fatal("delivery under the other identity failed")
			}

			from := rec.count()
			if !run(srv.URL, "synthetic-key-a").Delivered {
				t.Fatal("final run not delivered")
			}
			rec.mu.Lock()
			got := append([]string(nil), rec.actions[from:]...)
			rec.mu.Unlock()
			if len(got) < 2 || got[0] != "delta" || got[len(got)-1] != "snapshot" {
				t.Fatalf("final run sent %v; want the stale spooled delta, then a snapshot", got)
			}
		})
	}
}

// A stale chunk can replay successfully under one identity while the snapshot
// that should follow it is unconfirmed. The baseline saved under another
// identity no longer describes the receiver, so returning to that identity must
// send a snapshot, not an unchanged delta.
func TestUnconfirmedRepairDoesNotLeaveOtherBaselineUsable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("HOME", dir)
	var rec actionRecorder
	srv := rec.serve(t)

	cfg := config.Defaults()
	cfg.Profile = "minimal"
	cfg.Delta = true
	cfg.MaxRetries = 1
	cfg.StatePath = filepath.Join(dir, "state.json")
	run := func(key string) Result {
		t.Helper()
		c := cfg
		c.Endpoint = srv.URL
		c.APIKey = key
		res, err := Run(context.Background(), c, "test", nil)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return res
	}

	if !run("synthetic-key-a").Delivered {
		t.Fatal("baseline run under A not delivered")
	}
	rec.down.Store(true)
	if res := run("synthetic-key-a"); res.Delivered || res.Spooled == 0 {
		t.Fatalf("outage did not spool under A: %+v", res)
	}
	rec.down.Store(false)
	if !run("synthetic-key-b").Delivered {
		t.Fatal("delivery under B failed")
	}

	// Back on A: the spooled delta replays and succeeds, the snapshot fails.
	rec.failSnapshots.Store(true)
	from := rec.count()
	if res := run("synthetic-key-a"); res.Delivered || len(res.Unconfirmed) == 0 {
		t.Fatalf("snapshot under A should be unconfirmed: %+v", res)
	}
	rec.mu.Lock()
	replayed := append([]string(nil), rec.actions[from:]...)
	rec.mu.Unlock()
	if len(replayed) < 2 || replayed[0] != "delta" {
		t.Fatalf("run under A sent %v; want the spooled delta replayed first", replayed)
	}
	rec.failSnapshots.Store(false)

	from = rec.count()
	if !run("synthetic-key-b").Delivered {
		t.Fatal("return to B not delivered")
	}
	if got := rec.last(t, from); got != "snapshot" {
		t.Fatalf("return to B sent %q; the receiver was changed under A, so B's old baseline must not be used", got)
	}
}
