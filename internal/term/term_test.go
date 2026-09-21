package term

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Midtown-Technology-Group/sopdet/internal/progress"
)

func render(events ...progress.Event) string {
	var buf bytes.Buffer
	r := NewReporter(&buf, Options{Version: "1.2.3"})
	for _, e := range events {
		r.Emit(e)
	}
	return buf.String()
}

func TestNonTTYLogsEveryEntity(t *testing.T) {
	out := render(
		progress.Event{Kind: progress.KindStart, Data: map[string]any{"hostname": "HOST1", "profile": "quick", "source": "smbios_uuid"}},
		progress.Event{Kind: progress.KindPlan, Total: 2},
		progress.Event{Kind: progress.KindEntity, Entity: "host", Index: 1, Total: 2, OK: progress.Bool(true), Count: 1},
		progress.Event{Kind: progress.KindEntity, Entity: "tpm", Index: 2, Total: 2, OK: progress.Bool(true), Count: 1},
		progress.Event{Kind: progress.KindDone, Data: map[string]any{"entities": 2, "entity_errors": 0, "scan_id": "abc", "action": "snapshot"}},
	)
	for _, want := range []string{"device inventory", "HOST1", "1.2.3", "[1/2] host: 1 records", "[2/2] TPM: 1 records", "complete", "entities=2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("non-tty output should not contain ANSI escapes")
	}
}

func TestFailedEntityIsReported(t *testing.T) {
	out := render(progress.Event{
		Kind: progress.KindEntity, Entity: "processes", Index: 3, Total: 5,
		OK: progress.Bool(false), Message: "Access is denied",
	})
	if !strings.Contains(out, "processes: Access is denied") {
		t.Fatalf("failure not rendered:\n%s", out)
	}
}

func TestQuietSuppressesBanner(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf, Options{Version: "x", Quiet: true})
	r.Emit(progress.Event{Kind: progress.KindStart, Data: map[string]any{"hostname": "H"}})
	r.Emit(progress.Event{Kind: progress.KindEntity, Entity: "host", Index: 1, Total: 1, OK: progress.Bool(true)})
	if strings.Contains(buf.String(), "device inventory") {
		t.Fatalf("quiet mode printed banner:\n%s", buf.String())
	}
}

func TestPrettyLabels(t *testing.T) {
	cases := map[string]string{
		"os": "operating system", "tpm": "TPM", "network_interfaces": "network", "mystery_key": "mystery key",
	}
	for in, want := range cases {
		if got := pretty(in); got != want {
			t.Errorf("pretty(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVisibleLenIgnoresANSI(t *testing.T) {
	if got := visibleLen("\x1b[32mok\x1b[0m"); got != 2 {
		t.Fatalf("visibleLen = %d, want 2", got)
	}
	if got := visibleLen("plain"); got != 5 {
		t.Fatalf("visibleLen = %d, want 5", got)
	}
}

func TestBarBounds(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf, Options{})
	for _, tc := range []struct{ i, total int }{{0, 0}, {-1, 4}, {2, 4}, {9, 4}} {
		if got := r.bar(tc.i, tc.total); got == "" {
			t.Fatalf("empty bar for %+v", tc)
		}
	}
}
