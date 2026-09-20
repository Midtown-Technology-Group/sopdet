// Package collect runs per-entity collectors and assembles entity collections.
package collect

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// Session carries cross-cutting collection inputs.
type Session struct {
	Identity         schema.HostIdentifier
	Elevated         bool
	OS               string
	MaxListItems     int
	IncludeAppx      bool
	IncludeProcesses bool
}

// Collector produces records for one entity type.
type Collector interface {
	Name() string
	Level() int
	Collect(ctx context.Context, s *Session) ([]schema.Record, error)
}

// Run executes every collector at or below the requested level.
func Run(ctx context.Context, level int, s *Session) (map[string]*schema.EntityCollection, map[string]schema.EntityError) {
	entities := map[string]*schema.EntityCollection{}
	errs := map[string]schema.EntityError{}

	all := append(baseCollectors(), PlatformCollectors(s)...)
	for _, c := range all {
		if c.Level() > level {
			continue
		}
		if c.Name() == "appx_packages" && !s.IncludeAppx {
			continue
		}
		if c.Name() == "processes" && !s.IncludeProcesses {
			continue
		}
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		recs, err := runCollector(c, cctx, s)
		cancel()
		if err != nil {
			errs[c.Name()] = schema.EntityError{
				Error:      err.Error(),
				Gated:      looksGated(err.Error()),
				DurationMs: time.Since(start).Milliseconds(),
			}
			continue
		}
		if len(recs) > s.MaxListItems && s.MaxListItems > 0 {
			recs = recs[:s.MaxListItems]
		}
		entities[c.Name()] = schema.BuildEntity(recs, time.Now().UTC().Format("2006-01-02T15:04:05.0000000Z"))
	}
	return entities, errs
}

func runCollector(c Collector, ctx context.Context, s *Session) (recs []schema.Record, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collector panic: %v", r)
		}
	}()
	return c.Collect(ctx, s)
}

func looksGated(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range []string{"access is denied", "access denied", "not authorized", "privilege", "requires elevation", "0x80070005"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// OSName reports the runtime OS using the same vocabulary as the schema.
func OSName() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}
