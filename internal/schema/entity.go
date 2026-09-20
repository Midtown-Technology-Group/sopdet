package schema

import "fmt"

// BuildEntity completes raw collector records into an EntityCollection:
// it ensures unique keys, stamps observed_at, and computes fingerprints.
// A JSON round-trip is used to normalise numeric types before hashing.
func BuildEntity(records []Record, observedAt string) *EntityCollection {
	out := make([]Record, 0, len(records))
	seen := map[string]int{}
	for i, rec := range records {
		if rec == nil {
			continue
		}
		r := Record{}
		for k, v := range rec {
			r[k] = v
		}
		key, _ := r["key"].(string)
		if key == "" {
			key = fmt.Sprintf("item:%d", i)
		}
		if n, dup := seen[key]; dup {
			seen[key] = n + 1
			key = fmt.Sprintf("%s#%d", key, seen[key])
		} else {
			seen[key] = 1
		}
		r["key"] = key
		r["fingerprint"] = Fingerprint(r)
		r["observed_at"] = observedAt
		out = append(out, r)
	}
	fps := make([]string, len(out))
	for i, r := range out {
		fps[i], _ = r["fingerprint"].(string)
	}
	return &EntityCollection{
		Count:       len(out),
		Fingerprint: rollupFingerprint(len(out), fps),
		Records:     out,
	}
}
