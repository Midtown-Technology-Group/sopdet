package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
