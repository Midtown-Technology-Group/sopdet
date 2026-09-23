package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	deviceKeyPrefix       = "bfdk_"
	enrollmentTokenPrefix = "bfen_"
	controlKeyPrefix      = "bfck_"

	// rawKeySecretLen is len(token_urlsafe(32)) — the platform's frozen
	// secret component length.
	rawKeySecretLen = 43
)

// keyPattern mirrors the platform's frozen key formats
// (docs/architecture/device-control-plane.md): prefix_<uuid>_<43-char secret>.
var keyPattern = regexp.MustCompile(
	`^(bfdk|bfck|bfen)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Za-z0-9_-]{43}$`,
)

// DeviceState is the persisted serve identity. DeviceKey is a secret: this
// type intentionally has no String/GoString methods; never print it.
type DeviceState struct {
	BifrostURL string `json:"bifrost_url"`
	DeviceID   string `json:"device_id"`
	DeviceKey  string `json:"device_key"`
}

// ValidDeviceKeyFormat reports whether raw matches the frozen bfdk_ format.
func ValidDeviceKeyFormat(raw string) bool {
	return keyPattern.MatchString(raw) && strings.HasPrefix(raw, deviceKeyPrefix)
}

// ParseDeviceKeyID returns the device UUID embedded in a bfdk_ key.
func ParseDeviceKeyID(raw string) (string, bool) {
	if !ValidDeviceKeyFormat(raw) {
		return "", false
	}
	// prefix(5) + uuid(36) + "_" => id ends at index 41.
	return raw[5:41], true
}

// LoadDeviceState reads the persisted device state. A missing file returns
// the zero state and no error (first run).
func LoadDeviceState(path string) (DeviceState, error) {
	if path == "" {
		return DeviceState{}, fmt.Errorf("missing device state path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DeviceState{}, nil
		}
		return DeviceState{}, fmt.Errorf("read device state: %w", err)
	}
	var state DeviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return DeviceState{}, fmt.Errorf("parse device state: %w", err)
	}
	return state, nil
}

// SaveDeviceState persists the device state atomically with mode 0600
// (POSIX). On Windows the M5 installer applies the SYSTEM/Administrators
// DACL to the state directory; chmod is best-effort there.
func SaveDeviceState(path string, state DeviceState) error {
	if path == "" {
		return fmt.Errorf("missing device state path")
	}
	if state.DeviceKey == "" {
		return fmt.Errorf("refusing to persist empty device key")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".serve-*.json")
	if err != nil {
		return fmt.Errorf("write device state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write device state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod device state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write device state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("commit device state: %w", err)
	}
	return nil
}
