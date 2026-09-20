//go:build windows

package collect

import (
	"context"
	"fmt"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// PlatformIdentity reads the Windows machine GUID and elevation state.
func PlatformIdentity() (machineGUID, hardwareUUID *string, elevated bool) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		defer k.Close()
		if guid, _, err := k.GetStringValue("MachineGuid"); err == nil && guid != "" {
			machineGUID = &guid
		}
	}
	var csp []struct{ UUID string }
	if err := wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &csp); err == nil && len(csp) > 0 && csp[0].UUID != "" {
		hardwareUUID = &csp[0].UUID
	}
	token := windows.GetCurrentProcessToken()
	elevated = token.IsElevated()
	return machineGUID, hardwareUUID, elevated
}

// PlatformCollectors returns Windows-specific collectors.
func PlatformCollectors(_ *Session) []Collector {
	return append([]Collector{softwareCollector{}}, wmiCollectors()...)
}

type softwareCollector struct{}

func (softwareCollector) Name() string { return "software" }
func (softwareCollector) Level() int   { return levelQuick }

func (softwareCollector) Collect(_ context.Context, s *Session) ([]schema.Record, error) {
	type hive struct {
		root  registry.Key
		path  string
		scope string
		arch  string
	}
	hives := []hive{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "machine", "x64"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "machine", "x86"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "user", "auto"},
	}
	seen := map[string]bool{}
	out := []schema.Record{}
	for _, h := range hives {
		k, err := registry.OpenKey(h.root, h.path, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, name := range names {
			sub, err := registry.OpenKey(h.root, h.path+`\`+name, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			display, _, _ := sub.GetStringValue("DisplayName")
			if display == "" {
				sub.Close()
				continue
			}
			version, _, _ := sub.GetStringValue("DisplayVersion")
			publisher, _, _ := sub.GetStringValue("Publisher")
			installDate, _, _ := sub.GetStringValue("InstallDate")
			location, _, _ := sub.GetStringValue("InstallLocation")
			sizeKB, _, _ := sub.GetIntegerValue("EstimatedSize")
			sub.Close()

			id := fmt.Sprintf("%s|%s|%s", h.scope, display, version)
			if seen[id] {
				continue
			}
			seen[id] = true
			rec := schema.Record{
				"key":              id,
				"name":             display,
				"version":          version,
				"vendor":           publisher,
				"install_date":     normalizeInstallDate(installDate),
				"install_location": location,
				"scope":            h.scope,
				"architecture":     h.arch,
				"source":           "registry",
				"product_code":     name,
			}
			if sizeKB > 0 {
				rec["size_bytes"] = int64(sizeKB) * 1024
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

func normalizeInstallDate(v string) string {
	if len(v) == 8 {
		for _, c := range v {
			if c < '0' || c > '9' {
				return v
			}
		}
		return fmt.Sprintf("%s-%s-%s", v[0:4], v[4:6], v[6:8])
	}
	return v
}
