// Package state persists per-device fingerprints for delta scans.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// State is the last-known fingerprint set for a device.
type State struct {
	SchemaVersion   int                          `json:"schema_version"`
	ScanID          string                       `json:"scan_id"`
	ObservedAt      string                       `json:"observed_at"`
	Agent           string                       `json:"agent,omitempty"`
	FingerprintAlgo string                       `json:"fingerprint_algo"`
	Entities        map[string]map[string]string `json:"entities"`
}

// Load reads state, returning nil (no error) when the file is absent or empty.
func Load(path string) (*State, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes state atomically.
func Save(path string, s *State) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AsMaps extracts the key->fingerprint maps from state.
func (s *State) AsMaps() map[string]map[string]string {
	if s == nil || s.Entities == nil {
		return map[string]map[string]string{}
	}
	return s.Entities
}

// BuildDelta diffs current collections against the previous fingerprint maps.
func BuildDelta(entities map[string]*schema.EntityCollection, prev map[string]map[string]string) map[string]*schema.EntityDelta {
	out := make(map[string]*schema.EntityDelta, len(entities))
	for name, coll := range entities {
		old := prev[name]
		cur := map[string]string{}
		byKey := map[string]schema.Record{}
		for _, rec := range coll.Records {
			key, _ := rec["key"].(string)
			fp, _ := rec["fingerprint"].(string)
			cur[key] = fp
			byKey[key] = rec
		}
		d := &schema.EntityDelta{
			Count:   len(cur),
			Added:   []schema.Record{},
			Changed: []schema.Record{},
			Removed: []schema.RemovedStub{},
		}
		for key, fp := range cur {
			if _, ok := old[key]; !ok {
				d.Added = append(d.Added, byKey[key])
			} else if old[key] != fp {
				d.Changed = append(d.Changed, byKey[key])
			} else {
				d.Unchanged++
			}
		}
		for key, fp := range old {
			if _, ok := cur[key]; !ok {
				d.Removed = append(d.Removed, schema.RemovedStub{Key: key, PreviousFingerprint: fp})
			}
		}
		out[name] = d
	}
	return out
}

// Snapshot produces a State from built collections.
func Snapshot(scanID, observedAt, agent, algo string, entities map[string]*schema.EntityCollection) *State {
	maps := make(map[string]map[string]string, len(entities))
	for name, coll := range entities {
		m := make(map[string]string, len(coll.Records))
		for _, rec := range coll.Records {
			key, _ := rec["key"].(string)
			fp, _ := rec["fingerprint"].(string)
			m[key] = fp
		}
		maps[name] = m
	}
	return &State{
		SchemaVersion:   2,
		ScanID:          scanID,
		ObservedAt:      observedAt,
		Agent:           agent,
		FingerprintAlgo: algo,
		Entities:        maps,
	}
}
