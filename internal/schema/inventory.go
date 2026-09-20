// Package schema defines the device inventory envelope (contract v2).
package schema

// Record is one inventory entity record. Collectors populate the descriptive
// fields and set "key"; BuildEntity adds "fingerprint" and "observed_at".
type Record map[string]any

// EntityCollection is a full (snapshot) set of records for one entity type.
type EntityCollection struct {
	Count       int      `json:"count"`
	Fingerprint string   `json:"fingerprint"`
	Records     []Record `json:"records"`
	Summarized  bool     `json:"summarized,omitempty"`
	Omitted     int      `json:"omitted,omitempty"`
}

// RemovedStub marks a record deleted in a delta.
type RemovedStub struct {
	Key                 string `json:"key"`
	PreviousFingerprint string `json:"previous_fingerprint,omitempty"`
}

// EntityDelta is a delta set of changes for one entity type.
type EntityDelta struct {
	Count      int           `json:"count"`
	Added      []Record      `json:"added"`
	Changed    []Record      `json:"changed"`
	Removed    []RemovedStub `json:"removed"`
	Unchanged  int           `json:"unchanged"`
	Summarized bool          `json:"summarized,omitempty"`
	Omitted    int           `json:"omitted,omitempty"`
}

// HostIdentifier is the stable identity block.
type HostIdentifier struct {
	DeviceID       string  `json:"device_id"`
	DeviceIDSource string  `json:"device_id_source"`
	HardwareUUID   *string `json:"hardware_uuid"`
	MachineGUID    *string `json:"machine_guid"`
	InstanceID     string  `json:"instance_id"`
	Hostname       string  `json:"hostname"`
	FQDN           *string `json:"fqdn"`
}

// Agent describes the collector build.
type Agent struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Elevated bool   `json:"elevated"`
	Runtime  string `json:"runtime,omitempty"`
	Profile  string `json:"profile"`
	User     string `json:"user"`
}

// EntityError records a failed or elevation-gated collection.
type EntityError struct {
	Error      string `json:"error"`
	Gated      bool   `json:"gated"`
	DurationMs int64  `json:"durationMs"`
}

// Chunk describes a transport chunk when the envelope is split.
type Chunk struct {
	Index    int      `json:"index"`
	Count    int      `json:"count"`
	Entities []string `json:"entities"`
}

// Actions.
const (
	ActionSnapshot = "snapshot"
	ActionDelta    = "delta"
)

// Envelope is the top-level inventory document.
type Envelope struct {
	SchemaVersion  int                    `json:"schema_version"`
	ScanID         string                 `json:"scan_id"`
	BaseScanID     *string                `json:"base_scan_id"`
	Action         string                 `json:"action"`
	Partial        bool                   `json:"partial"`
	HostIdentifier HostIdentifier         `json:"host_identifier"`
	CalendarTime   string                 `json:"calendar_time"`
	UnixTime       int64                  `json:"unix_time"`
	ReceivedAt     *string                `json:"received_at"`
	Decorators     map[string]any         `json:"decorators"`
	Agent          Agent                  `json:"agent"`
	Truncated      []string               `json:"truncated"`
	EntityErrors   map[string]EntityError `json:"entity_errors"`
	Entities       map[string]any         `json:"entities"`
	Chunk          *Chunk                 `json:"chunk,omitempty"`
}

// CloneWithEntities returns a copy of the envelope carrying a subset of
// entities plus a chunk descriptor, for transport chunking.
func (e *Envelope) CloneWithEntities(entities map[string]any, chunk *Chunk) *Envelope {
	c := *e
	c.Entities = entities
	c.Chunk = chunk
	return &c
}
