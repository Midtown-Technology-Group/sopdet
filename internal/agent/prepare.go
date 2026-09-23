package agent

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// PrepareServe resolves the device identity for serve mode and refuses to
// continue without a Bifrost URL plus either an explicit/persisted device
// key or an enrollment token (M0 fail-closed posture; #838).
//
// Precedence for the key: flag/env key > persisted state > enrollment.
// Secrets never appear in returned errors.
func PrepareServe(
	ctx context.Context,
	cfg ServeConfig,
	client *http.Client,
) (DeviceState, error) {
	if err := ValidateBifrostURL(cfg.BifrostURL); err != nil {
		return DeviceState{}, fmt.Errorf("refusing to serve: %w", err)
	}
	baseURL := strings.TrimRight(cfg.BifrostURL, "/")

	if cfg.DeviceKey != "" {
		if !ValidDeviceKeyFormat(cfg.DeviceKey) {
			return DeviceState{}, fmt.Errorf(
				"refusing to serve: device key has unexpected format",
			)
		}
		deviceID, ok := ParseDeviceKeyID(cfg.DeviceKey)
		if !ok {
			return DeviceState{}, fmt.Errorf(
				"refusing to serve: device key has unexpected format",
			)
		}
		state := DeviceState{
			BifrostURL: baseURL,
			DeviceID:   deviceID,
			DeviceKey:  cfg.DeviceKey,
		}
		if err := persistIfChanged(cfg.StatePath, state); err != nil {
			return DeviceState{}, err
		}
		return state, nil
	}

	persisted, loadErr := LoadDeviceState(cfg.StatePath)
	if loadErr == nil && persisted.DeviceKey != "" {
		if !ValidDeviceKeyFormat(persisted.DeviceKey) {
			return DeviceState{}, fmt.Errorf(
				"refusing to serve: persisted device key has unexpected format",
			)
		}
		if persisted.BifrostURL != "" && persisted.BifrostURL != baseURL {
			return DeviceState{}, fmt.Errorf(
				"refusing to serve: persisted key belongs to a different Bifrost URL " +
					"(delete the state file or pass the matching -bifrost-url)",
			)
		}
		if persisted.BifrostURL == "" {
			persisted.BifrostURL = baseURL
		}
		return persisted, nil
	}

	if cfg.EnrollmentToken != "" {
		// The enrollment token is single-use: fail before spending it if the
		// state file cannot be written (read-only dir, permissions, etc.).
		if err := ensureStateWritable(cfg.StatePath); err != nil {
			return DeviceState{}, fmt.Errorf(
				"refusing to serve: %w (fix before enrolling; token not consumed)", err,
			)
		}
		state, err := Enroll(ctx, baseURL, cfg.EnrollmentToken, client)
		if err != nil {
			return DeviceState{}, fmt.Errorf("refusing to serve: %w", err)
		}
		if err := SaveDeviceState(cfg.StatePath, state); err != nil {
			return DeviceState{}, fmt.Errorf("refusing to serve: %w", err)
		}
		return state, nil
	}

	if loadErr != nil {
		return DeviceState{}, fmt.Errorf("refusing to serve: %w", loadErr)
	}

	return DeviceState{}, fmt.Errorf(
		"refusing to serve: no device key (set -device-key or SOPDET_DEVICE_KEY), "+
			"no persisted key at %s, and no enrollment token (-enroll-token / "+
			"SOPDET_ENROLLMENT_TOKEN)",
		cfg.StatePath,
	)
}

// persistIfChanged writes the state file when its content differs from what
// is already on disk, so adopting an env/flag key does not churn the file.
func persistIfChanged(path string, state DeviceState) error {
	existing, err := LoadDeviceState(path)
	if err == nil && existing == state {
		return nil
	}
	if err := SaveDeviceState(path, state); err != nil {
		return fmt.Errorf("refusing to serve: %w", err)
	}
	return nil
}

// ensureStateWritable verifies the state directory can be created and a
// temporary file written, without touching the state file itself.
func ensureStateWritable(path string) error {
	if path == "" {
		return fmt.Errorf("missing device state path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state dir not writable: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("state dir not writable: %w", err)
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)
	return nil
}

// ServeReadyMessage describes a prepared serve identity without leaking the
// device key.
func ServeReadyMessage(state DeviceState, statePath string) string {
	return fmt.Sprintf(
		"serve ready: device %s -> %s (state: %s)",
		state.DeviceID, state.BifrostURL, statePath,
	)
}
