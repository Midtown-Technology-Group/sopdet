package schema

import "testing"

func TestFingerprintDeterministicAndVolatileExcluded(t *testing.T) {
	base := Record{"key": "a", "name": "X", "version": "1", "vendor": "Acme"}
	fp1 := Fingerprint(base)
	fp2 := Fingerprint(Record{"vendor": "Acme", "version": "1", "name": "X", "key": "a"})
	if fp1 != fp2 {
		t.Fatalf("fingerprint not order-independent: %s vs %s", fp1, fp2)
	}
	if len(fp1) != 64 {
		t.Fatalf("expected sha256 hex, got %q", fp1)
	}

	changed := Record{"key": "a", "name": "X", "version": "2", "vendor": "Acme"}
	if Fingerprint(changed) == fp1 {
		t.Fatal("version change did not alter fingerprint")
	}

	withVolatile := Record{"key": "a", "name": "X", "version": "1", "vendor": "Acme", "free_bytes": 123, "uptime_seconds": 9}
	if Fingerprint(withVolatile) != fp1 {
		t.Fatal("volatile fields must not affect fingerprint")
	}
}

func TestBuildEntityKeysAndRollup(t *testing.T) {
	recs := []Record{
		{"key": "x", "name": "one"},
		{"key": "x", "name": "two"},
		{"name": "nokey"},
	}
	e := BuildEntity(recs, "2026-01-01T00:00:00Z")
	if e.Count != 3 {
		t.Fatalf("count=%d", e.Count)
	}
	keys := []string{}
	for _, r := range e.Records {
		k, _ := r["key"].(string)
		keys = append(keys, k)
		if r["observed_at"] != "2026-01-01T00:00:00Z" {
			t.Fatalf("observed_at missing")
		}
		if fp, _ := r["fingerprint"].(string); len(fp) != 64 {
			t.Fatalf("record fingerprint missing: %v", r["fingerprint"])
		}
	}
	if keys[0] != "x" || keys[1] != "x#2" {
		t.Fatalf("duplicate keys not disambiguated: %v", keys)
	}

	e2 := BuildEntity(recs, "2026-01-01T00:00:00Z")
	if e.Fingerprint != e2.Fingerprint {
		t.Fatal("rollup fingerprint not deterministic")
	}
}
