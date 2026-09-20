package app

import (
	"context"
	"os"
	"path/filepath"
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

	res, err := Run(context.Background(), cfg, "test")
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
