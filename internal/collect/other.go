//go:build !windows && !linux && !darwin

package collect

import "os"

// PlatformIdentity reports elevation on other Unix-like systems.
func PlatformIdentity() (machineGUID, hardwareUUID *string, elevated bool) {
	return nil, nil, os.Geteuid() == 0
}

// PlatformCollectors returns OS-specific collectors (none for this platform).
func PlatformCollectors(_ *Session) []Collector {
	return nil
}
