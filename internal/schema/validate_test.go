package schema

import (
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compileInventorySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open("../../schema/inventory.schema.json")
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("inventory.schema.json", doc); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	sch, err := c.Compile("inventory.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func loadJSONFile(t *testing.T, path string) any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	v, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

func TestSampleOutputValidatesAgainstSchema(t *testing.T) {
	sch := compileInventorySchema(t)
	v := loadJSONFile(t, "../../testdata/sample-output.json")
	if err := sch.Validate(v); err != nil {
		t.Fatalf("sample output failed schema: %v", err)
	}
}

func TestBuiltEnvelopeValidates(t *testing.T) {
	sch := compileInventorySchema(t)
	entities := map[string]any{
		"os":       BuildEntity([]Record{{"key": "os", "name": "TestOS", "build": "1"}}, "2026-01-01T00:00:00Z"),
		"software": BuildEntity([]Record{{"key": "m|A|1", "name": "A"}}, "2026-01-01T00:00:00Z"),
	}
	env := &Envelope{
		SchemaVersion: 2,
		ScanID:        "11111111-1111-1111-1111-111111111111",
		Action:        ActionSnapshot,
		HostIdentifier: HostIdentifier{
			DeviceID:       "00000000-0000-4000-8000-0000000000aa",
			DeviceIDSource: "machine_guid",
			InstanceID:     "00000000-0000-4000-8000-0000000000cc",
			Hostname:       "TEST",
		},
		CalendarTime: "2026-01-01T00:00:00Z",
		UnixTime:     1767225600,
		Decorators:   map[string]any{},
		Agent:        Agent{Name: "sopdet", Version: "test", OS: "linux", Arch: "amd64", Profile: "quick"},
		Truncated:    []string{},
		EntityErrors: map[string]EntityError{},
		Entities:     entities,
	}
	b, err := jsonMarshal(env)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonschema.UnmarshalJSON(bytesReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("built envelope failed schema: %v", err)
	}
}

func TestChunkEnvelopeValidates(t *testing.T) {
	sch := compileInventorySchema(t)
	src := loadJSONFile(t, "../../testdata/sample-output.json")
	_ = src // schema already covers `chunk`; construct a minimal chunked delta
	env := &Envelope{
		SchemaVersion: 2,
		ScanID:        "11111111-1111-1111-1111-111111111111",
		BaseScanID:    ptr("22222222-2222-2222-2222-222222222222"),
		Action:        ActionDelta,
		HostIdentifier: HostIdentifier{
			DeviceID:       "00000000-0000-4000-8000-0000000000aa",
			DeviceIDSource: "machine_guid",
			InstanceID:     "00000000-0000-4000-8000-0000000000cc",
			Hostname:       "TEST",
		},
		CalendarTime: "2026-01-01T00:00:00Z",
		UnixTime:     1767225600,
		Decorators:   map[string]any{},
		Agent:        Agent{Name: "sopdet", Version: "test", OS: "linux", Arch: "amd64", Profile: "quick"},
		Truncated:    []string{},
		EntityErrors: map[string]EntityError{},
		Entities: map[string]any{
			"software": &EntityDelta{Count: 1, Added: []Record{{"key": "k", "fingerprint": fp64(), "observed_at": "2026-01-01T00:00:00Z"}}, Changed: []Record{}, Removed: []RemovedStub{}, Unchanged: 0},
		},
		Chunk: &Chunk{Index: 0, Count: 2, Entities: []string{"software"}},
	}
	b, err := jsonMarshal(env)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonschema.UnmarshalJSON(bytesReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("chunk envelope failed schema: %v", err)
	}
}
