package main

import (
	"strings"
	"testing"
)

func mkEnv(t *testing.T, entities map[string][]map[string]any, errs []string) envelope {
	t.Helper()
	e := envelope{Entities: map[string]entity{}, EntityErrors: map[string]any{}}
	for name, recs := range entities {
		e.Entities[name] = entity{Records: recs}
	}
	for _, er := range errs {
		e.EntityErrors[er] = map[string]any{"error": "x"}
	}
	return e
}

func rec(key string, fields map[string]any) map[string]any {
	r := map[string]any{"key": key, "fingerprint": strings.Repeat("a", 64), "observed_at": "2026-01-01T00:00:00Z"}
	for k, v := range fields {
		r[k] = v
	}
	return r
}

func TestComparePass(t *testing.T) {
	wifi := []map[string]any{rec("wifi:eth", map[string]any{"ssid": "Corp", "signal_percent": nil})}
	entities := map[string][]map[string]any{
		"wifi_networks": wifi,
		"os":            {rec("os", map[string]any{"build": "1"})},
	}
	rep := compare(mkEnv(t, entities, nil), mkEnv(t, entities, nil))
	if len(rep.failures) > 0 {
		t.Fatalf("failures: %v", rep.failures)
	}
}

func TestCompareEntitySetMismatch(t *testing.T) {
	goEnv := mkEnv(t, map[string][]map[string]any{"os": {rec("os", nil)}}, nil)
	psEnv := mkEnv(t, map[string][]map[string]any{"os": {rec("os", nil)}, "tpm": {rec("tpm", nil)}}, nil)
	rep := compare(goEnv, psEnv)
	if len(rep.failures) != 1 || !strings.Contains(rep.failures[0], "tpm") {
		t.Fatalf("failures: %v", rep.failures)
	}
}

func TestCompareEntityErrorsMismatch(t *testing.T) {
	ents := map[string][]map[string]any{"os": {rec("os", nil)}}
	rep := compare(mkEnv(t, ents, []string{"tpm"}), mkEnv(t, ents, nil))
	if len(rep.failures) != 1 || !strings.Contains(rep.failures[0], "entity_errors") {
		t.Fatalf("failures: %v", rep.failures)
	}
}

func TestCompareCountMismatch(t *testing.T) {
	goEnv := mkEnv(t, map[string][]map[string]any{"os": {rec("os", nil), rec("os2", nil)}}, nil)
	psEnv := mkEnv(t, map[string][]map[string]any{"os": {rec("os", nil)}}, nil)
	rep := compare(goEnv, psEnv)
	if len(rep.failures) == 0 {
		t.Fatal("expected count failure for stable entity")
	}
	// Warn-only entities downgrade counts to warnings.
	goW := mkEnv(t, map[string][]map[string]any{"processes": {rec("a", nil), rec("b", nil)}}, nil)
	psW := mkEnv(t, map[string][]map[string]any{"processes": {rec("a", nil)}}, nil)
	repW := compare(goW, psW)
	if len(repW.failures) > 0 || len(repW.warnings) != 1 {
		t.Fatalf("warn entity: failures=%v warnings=%v", repW.failures, repW.warnings)
	}
}

func TestCompareKeyMismatch(t *testing.T) {
	goEnv := mkEnv(t, map[string][]map[string]any{"os": {rec("os", nil)}}, nil)
	psEnv := mkEnv(t, map[string][]map[string]any{"os": {rec("os-other", nil)}}, nil)
	rep := compare(goEnv, psEnv)
	if len(rep.failures) == 0 {
		t.Fatal("expected key failure")
	}
}

func TestCompareNetworkAsymmetric(t *testing.T) {
	mk := func(mac string) map[string]any {
		return rec("nic:x", map[string]any{"mac_address": mac, "up": true})
	}
	// PS NIC missing from Go fails.
	rep := compare(
		mkEnv(t, map[string][]map[string]any{"network_interfaces": {mk("aa:bb")}}, nil),
		mkEnv(t, map[string][]map[string]any{"network_interfaces": {mk("aa:bb"), mk("cc:dd")}}, nil),
	)
	if len(rep.failures) == 0 {
		t.Fatal("expected failure for PS NIC missing from Go")
	}
	// Go extras pass (non-IP interfaces), with info.
	rep2 := compare(
		mkEnv(t, map[string][]map[string]any{"network_interfaces": {mk("aa:bb"), mk("cc:dd")}}, nil),
		mkEnv(t, map[string][]map[string]any{"network_interfaces": {mk("aa:bb")}}, nil),
	)
	if len(rep2.failures) > 0 {
		t.Fatalf("go extras should pass: %v", rep2.failures)
	}
}

func TestCompareFieldDrift(t *testing.T) {
	// New entity: strict.
	goNew := mkEnv(t, map[string][]map[string]any{"routes": {rec("r", map[string]any{"gateway": "g", "extra_go": 1})}}, nil)
	psNew := mkEnv(t, map[string][]map[string]any{"routes": {rec("r", map[string]any{"gateway": "g"})}}, nil)
	rep := compare(goNew, psNew)
	if len(rep.failures) != 1 || !strings.Contains(rep.failures[0], "extra_go") {
		t.Fatalf("new-entity drift should fail: %v", rep.failures)
	}
	// Legacy entity: warn-only.
	goLeg := mkEnv(t, map[string][]map[string]any{"software": {rec("s", map[string]any{"name": "n", "extra_go": 1})}}, nil)
	psLeg := mkEnv(t, map[string][]map[string]any{"software": {rec("s", map[string]any{"name": "n"})}}, nil)
	repLeg := compare(goLeg, psLeg)
	if len(repLeg.failures) > 0 || len(repLeg.warnings) != 1 {
		t.Fatalf("legacy drift should warn: failures=%v warnings=%v", repLeg.failures, repLeg.warnings)
	}
	// Null-valued fields are dropped on both sides.
	goNull := mkEnv(t, map[string][]map[string]any{"routes": {rec("r", map[string]any{"gateway": nil})}}, nil)
	psNull := mkEnv(t, map[string][]map[string]any{"routes": {rec("r", map[string]any{})}}, nil)
	repNull := compare(goNull, psNull)
	if len(repNull.failures) > 0 {
		t.Fatalf("null normalization: %v", repNull.failures)
	}
}
