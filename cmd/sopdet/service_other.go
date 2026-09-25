//go:build !windows

package main

import "github.com/Midtown-Technology-Group/sopdet/internal/agent"

// maybeRunAsService is a no-op outside Windows: there is no service control
// manager, so console serve mode always uses the signal-driven path.
func maybeRunAsService(_ string, _ agent.ServeConfig) (bool, int) {
	return false, 0
}
