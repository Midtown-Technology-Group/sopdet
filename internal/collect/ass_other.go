//go:build !windows && !linux && !darwin

package collect

import "github.com/Midtown-Technology-Group/sopdet/internal/schema"

// enrichNetworkInterfaces is a no-op on platforms without an assessment
// enrichment source; base NIC fields stand alone.
func enrichNetworkInterfaces(_ []schema.Record) {}
