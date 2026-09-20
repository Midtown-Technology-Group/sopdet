package collect

import (
	"context"
	"fmt"
	"runtime"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// Levels: 0 minimal, 1 quick, 2 full.
const (
	levelMinimal = 0
	levelQuick   = 1
	levelFull    = 2
)

func baseCollectors() []Collector {
	common := []Collector{hostCollector{}, volumesCollector{}, networkCollector{}}
	if runtime.GOOS == "windows" {
		return common
	}
	return append(common, osCollector{}, hardwareCollector{}, processorsCollector{}, memoryCollector{})
}

type hostCollector struct{}

func (hostCollector) Name() string { return "host" }
func (hostCollector) Level() int   { return levelMinimal }
func (hostCollector) Collect(_ context.Context, s *Session) ([]schema.Record, error) {
	fqdn := s.Identity.FQDN
	return []schema.Record{{
		"key":      "host",
		"hostname": s.Identity.Hostname,
		"fqdn":     fqdn,
	}}, nil
}

type osCollector struct{}

func (osCollector) Name() string { return "os" }
func (osCollector) Level() int   { return levelMinimal }
func (osCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	info, err := host.Info()
	if err != nil {
		return nil, err
	}
	return []schema.Record{{
		"key":                 "os",
		"hostname":            info.Hostname,
		"name":                info.Platform,
		"version":             info.PlatformVersion,
		"build":               info.KernelVersion,
		"platform":            info.OS,
		"platform_like":       info.PlatformFamily,
		"arch":                runtime.GOARCH,
		"uptime_seconds":      info.Uptime, // volatile: excluded from fingerprint
		"virtualization_role": info.VirtualizationRole,
	}}, nil
}

type hardwareCollector struct{}

func (hardwareCollector) Name() string { return "hardware" }
func (hardwareCollector) Level() int   { return levelMinimal }
func (hardwareCollector) Collect(_ context.Context, s *Session) ([]schema.Record, error) {
	vm, _ := mem.VirtualMemory()
	rec := schema.Record{"key": "hardware"}
	if vm != nil {
		rec["ram_total_bytes"] = int64(vm.Total)
	}
	infos, _ := cpu.Info()
	if len(infos) > 0 {
		rec["cpu_name"] = infos[0].ModelName
		rec["cpu_cores"] = infos[0].Cores
	}
	rec["virtual_machine"] = false
	return []schema.Record{rec}, nil
}

type processorsCollector struct{}

func (processorsCollector) Name() string { return "processors" }
func (processorsCollector) Level() int   { return levelQuick }
func (processorsCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	infos, err := cpu.Info()
	if err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(infos))
	for i, ci := range infos {
		out = append(out, schema.Record{
			"key":       fmt.Sprintf("cpu:%d", i),
			"name":      ci.ModelName,
			"cores":     ci.Cores,
			"mhz":       ci.Mhz,
			"vendor_id": ci.VendorID,
		})
	}
	return out, nil
}

type memoryCollector struct{}

func (memoryCollector) Name() string { return "memory_modules" }
func (memoryCollector) Level() int   { return levelQuick }
func (memoryCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	// Per-DIMM detail requires WMI/SMBIOS; the cross-platform summary is one
	// synthetic record. Windows collector replaces this on that platform.
	vm, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	return []schema.Record{{
		"key":        "memory:total",
		"size_bytes": int64(vm.Total),
		"source":     "gopsutil",
	}}, nil
}

type volumesCollector struct{}

func (volumesCollector) Name() string { return "volumes" }
func (volumesCollector) Level() int   { return levelMinimal }
func (volumesCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(parts))
	for _, p := range parts {
		rec := schema.Record{
			"key":         "volume:" + p.Mountpoint,
			"mountpoint":  p.Mountpoint,
			"device":      p.Device,
			"file_system": p.Fstype,
		}
		if u, err := disk.Usage(p.Mountpoint); err == nil && u != nil {
			rec["capacity_bytes"] = int64(u.Total)
			rec["free_bytes"] = int64(u.Free)
			rec["used_percent"] = u.UsedPercent
		}
		out = append(out, rec)
	}
	return out, nil
}

type networkCollector struct{}

func (networkCollector) Name() string { return "network_interfaces" }
func (networkCollector) Level() int   { return levelMinimal }
func (networkCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	ifaces, err := gnet.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(ifaces))
	for _, ni := range ifaces {
		addrs := make([]string, 0, len(ni.Addrs))
		for _, a := range ni.Addrs {
			addrs = append(addrs, a.Addr)
		}
		out = append(out, schema.Record{
			"key":          "nic:" + ni.Name,
			"adapter_name": ni.Name,
			"mac_address":  ni.HardwareAddr,
			"mtu":          ni.MTU,
			"ip_addresses": addrs,
			"up":           ni.Flags != nil && contains(ni.Flags, "up"),
		})
	}
	return out, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
