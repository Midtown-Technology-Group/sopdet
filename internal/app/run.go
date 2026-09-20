// Package app wires collection, delta state, size budgeting, and delivery.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Midtown-Technology-Group/sopdet/internal/collect"
	"github.com/Midtown-Technology-Group/sopdet/internal/config"
	"github.com/Midtown-Technology-Group/sopdet/internal/ingest"
	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
	"github.com/Midtown-Technology-Group/sopdet/internal/state"
)

// Result summarises a run.
type Result struct {
	Envelope   *schema.Envelope
	Delivered  bool
	Chunks     int
	Spooled    int
	Summarized bool
}

// Run executes one inventory scan.
func Run(ctx context.Context, cfg config.Config, agentVersion string) (Result, error) {
	identity, elevated, err := buildIdentity()
	if err != nil {
		return Result{}, err
	}

	sess := &collect.Session{
		Identity:         identity,
		Elevated:         elevated,
		OS:               collect.OSName(),
		MaxListItems:     cfg.MaxListItems,
		IncludeAppx:      cfg.IncludeAppx,
		IncludeProcesses: cfg.IncludeProcesses,
	}
	entities, entityErrs := collect.Run(ctx, config.Level(cfg.Profile), sess)

	truncated := []string{}
	summarized := enforceBudget(entities, cfg.MaxPayloadBytes, &truncated)

	action := schema.ActionSnapshot
	var base *string
	outEntities := toAny(entities)
	statePath := cfg.StatePath
	if statePath == "" {
		statePath = filepath.Join(defaultStateDir(), "state.json")
	}
	if cfg.Delta {
		st, err := state.Load(statePath)
		if err != nil {
			return Result{}, err
		}
		if st != nil && len(st.AsMaps()) > 0 {
			if st.ScanID != "" {
				base = &st.ScanID
			}
			action = schema.ActionDelta
			outEntities = deltaToAny(state.BuildDelta(entities, st.AsMaps()))
		}
	}

	scanID := uuid.NewString()
	now := time.Now().UTC()
	env := &schema.Envelope{
		SchemaVersion:  2,
		ScanID:         scanID,
		BaseScanID:     base,
		Action:         action,
		Partial:        cfg.Profile != "full",
		HostIdentifier: identity,
		CalendarTime:   now.Format("2006-01-02T15:04:05.0000000Z"),
		UnixTime:       now.Unix(),
		ReceivedAt:     nil,
		Decorators:     decorators(sess, elevated),
		Agent: schema.Agent{
			Name:     "sopdet",
			Version:  agentVersion,
			OS:       collect.OSName(),
			Arch:     runtime.GOARCH,
			Elevated: elevated,
			Runtime:  "go" + strings.TrimPrefix(runtime.Version(), "go"),
			Profile:  cfg.Profile,
			User:     currentUser(),
		},
		Truncated:    truncated,
		EntityErrors: entityErrs,
		Entities:     outEntities,
	}

	if cfg.OutputPath != "" {
		pretty, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(cfg.OutputPath, pretty, 0o600); err != nil {
			return Result{}, err
		}
	}

	res := Result{Envelope: env, Summarized: summarized}

	if cfg.Endpoint != "" && !cfg.DryRun {
		ir, err := ingest.Send(env, ingest.Options{
			Endpoint:   cfg.Endpoint,
			APIKey:     cfg.APIKey,
			Compress:   cfg.Compress,
			ChunkBytes: cfg.ChunkBytes,
			MaxRetries: cfg.MaxRetries,
			Proxy:      cfg.Proxy,
			SpoolDir:   filepath.Join(defaultStateDir(), "spool"),
			ScanID:     scanID,
		})
		if err != nil {
			return res, err
		}
		res.Delivered = ir.Delivered
		res.Chunks = ir.Chunks
		res.Spooled = ir.Spooled
	} else {
		res.Delivered = true
		if cfg.OutputPath == "" {
			compact, err := json.Marshal(env)
			if err != nil {
				return res, err
			}
			fmt.Println(string(compact))
		}
	}

	if res.Delivered && !summarized {
		snap := state.Snapshot(scanID, env.CalendarTime, env.Agent.Version, schema.FingerprintAlgo, entities)
		if err := state.Save(statePath, snap); err != nil {
			return res, err
		}
	}
	return res, nil
}

func toAny(entities map[string]*schema.EntityCollection) map[string]any {
	out := make(map[string]any, len(entities))
	for k, v := range entities {
		out[k] = v
	}
	return out
}

func deltaToAny(d map[string]*schema.EntityDelta) map[string]any {
	out := make(map[string]any, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

// enforceBudget trims the largest collections until the compact JSON fits.
func enforceBudget(entities map[string]*schema.EntityCollection, max int64, truncated *[]string) bool {
	if max <= 0 {
		return false
	}
	summarized := false
	for guard := 0; guard < 40; guard++ {
		b, err := json.Marshal(entities)
		if err != nil || int64(len(b)) <= max {
			break
		}
		name, best := "", 0
		for n, c := range entities {
			if len(c.Records) > best {
				name, best = n, len(c.Records)
			}
		}
		if name == "" || best <= 1 {
			break
		}
		c := entities[name]
		keep := best / 2
		if keep < 1 {
			keep = 1
		}
		c.Records = c.Records[:keep]
		c.Summarized = true
		c.Omitted += best - keep
		*truncated = append(*truncated, fmt.Sprintf("%s.records summarized (-%d)", name, best-keep))
		summarized = true
	}
	return summarized
}

func buildIdentity() (schema.HostIdentifier, bool, error) {
	hostname, _ := os.Hostname()
	guid, hw, elevated := collect.PlatformIdentity()
	instance, err := instanceID()
	if err != nil {
		return schema.HostIdentifier{}, elevated, err
	}

	deviceID, source := "", ""
	switch {
	case guid != nil && *guid != "":
		deviceID, source = *guid, "machine_guid"
	case hw != nil && *hw != "":
		deviceID, source = *hw, "smbios_uuid"
	default:
		deviceID, source = instance, "instance"
	}
	fqdn := hostname
	return schema.HostIdentifier{
		DeviceID:       deviceID,
		DeviceIDSource: source,
		HardwareUUID:   hw,
		MachineGUID:    guid,
		InstanceID:     instance,
		Hostname:       hostname,
		FQDN:           &fqdn,
	}, elevated, nil
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "sopdet")
		}
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "sopdet")
	}
	return ".sopdet"
}

func instanceID() (string, error) {
	dir := defaultStateDir()
	path := filepath.Join(dir, "instance-id")
	if data, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v, nil
		}
	}
	id := uuid.NewString()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return id, err
	}
	if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
		return id, err
	}
	return id, nil
}

func currentUser() string {
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	if runtime.GOOS == "windows" {
		if domain := os.Getenv("USERDOMAIN"); domain != "" {
			return domain + `\` + name
		}
	}
	return name
}

func decorators(s *collect.Session, elevated bool) map[string]any {
	d := map[string]any{
		"username":    currentUser(),
		"os_platform": collect.OSName(),
		"is_elevated": elevated,
	}
	if s.Identity.Hostname != "" {
		d["hostname"] = s.Identity.Hostname
	}
	return d
}
