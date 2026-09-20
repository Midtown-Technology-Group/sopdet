package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// FingerprintAlgo tags the fingerprint algorithm. It intentionally differs
// from the PowerShell agent's canonicalization, so delta baselines are not
// shared across implementations.
const FingerprintAlgo = "sha256-canonical-json/v1"

// volatileKeys are excluded from fingerprints: telemetry that changes every
// scan and must not mark inventory as changed.
var volatileKeys = map[string]struct{}{
	"free_bytes":                 {},
	"used_percent":               {},
	"percent_remaining":          {},
	"run_time_minutes":           {},
	"uptime_seconds":             {},
	"ram_free_bytes":             {},
	"ram_usage_percent":          {},
	"estimated_charge_remaining": {},
}

// Fingerprint returns the stable content hash of a record. encoding/json sorts
// map keys, giving deterministic bytes; volatile fields are dropped.
func Fingerprint(rec Record) string {
	filtered := make(map[string]any, len(rec))
	for k, v := range rec {
		if _, skip := volatileKeys[k]; skip {
			continue
		}
		filtered[k] = v
	}
	b, err := json.Marshal(filtered)
	if err != nil {
		b = []byte(err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// rollupFingerprint hashes the ordered set of record fingerprints so the
// collection-level fingerprint changes iff its membership/contents change.
func rollupFingerprint(count int, fingerprints []string) string {
	sorted := append([]string(nil), fingerprints...)
	sort.Strings(sorted)
	payload := struct {
		Count        int      `json:"count"`
		Fingerprints []string `json:"fingerprints"`
	}{count, sorted}
	b, err := json.Marshal(payload)
	if err != nil {
		b = []byte(err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
