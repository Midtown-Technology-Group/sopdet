//go:build darwin

package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// PlatformIdentity reads the hardware UUID from ioreg on macOS.
func PlatformIdentity() (machineGUID, hardwareUUID *string, elevated bool) {
	out, err := runCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err == nil {
		if m := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`).FindStringSubmatch(out); len(m) == 2 {
			uuid := m[1]
			hardwareUUID = &uuid
		}
	}
	return nil, hardwareUUID, os.Geteuid() == 0
}

// PlatformCollectors returns the macOS-specific collector set.
func PlatformCollectors(_ *Session) []Collector {
	return []Collector{
		macHardwareCollector{},
		macBiosCollector{},
		macVirtualizationCollector{},
		macSoftwareCollector{},
		macGraphicsCollector{},
		macTPMCollector{},
		macLocalUserCollector{},
		macListeningPortCollector{},
	}
}

func systemProfiler(dataType string) ([]map[string]any, error) {
	out, err := runCommand("system_profiler", "-json", dataType)
	if err != nil {
		return nil, err
	}
	var doc map[string][]map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, err
	}
	items, ok := doc[dataType]
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("no %s data", dataType)
	}
	return items, nil
}

func getStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func parseMemoryBytes(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	switch strings.ToUpper(fields[1]) {
	case "GB":
		return int64(n * 1024 * 1024 * 1024)
	case "MB":
		return int64(n * 1024 * 1024)
	case "TB":
		return int64(n * 1024 * 1024 * 1024 * 1024)
	default:
		return int64(n)
	}
}

type macHardwareCollector struct{}

func (macHardwareCollector) Name() string { return "hardware" }
func (macHardwareCollector) Level() int   { return levelMinimal }
func (macHardwareCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	items, err := systemProfiler("SPHardwareDataType")
	if err != nil {
		return nil, err
	}
	hw := items[0]
	rec := schema.Record{
		"key":           "hardware",
		"manufacturer":  "Apple Inc.",
		"model":         getStr(hw, "model_name"),
		"system_type":   getStr(hw, "model_identifier"),
		"cpu_name":      getStr(hw, "chip_type"),
		"system_serial": getStr(hw, "serial_number"),
	}
	if cpu := getStr(hw, "processor_name"); cpu != "" && rec["cpu_name"] == "" {
		rec["cpu_name"] = cpu
	}
	if mem := getStr(hw, "physical_memory"); mem != "" {
		rec["ram_total_bytes"] = parseMemoryBytes(mem)
	}
	vm := "Physical"
	if strings.Contains(strings.ToLower(rec["system_type"].(string)), "vm") {
		vm = "VirtualMachine"
	}
	rec["vm_system"] = vm
	rec["virtual_machine"] = vm != "Physical"
	return []schema.Record{rec}, nil
}

type macBiosCollector struct{}

func (macBiosCollector) Name() string { return "bios" }
func (macBiosCollector) Level() int   { return levelQuick }
func (macBiosCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	items, err := systemProfiler("SPHardwareDataType")
	if err != nil {
		return nil, err
	}
	hw := items[0]
	rec := schema.Record{
		"key":           "bios",
		"manufacturer":  "Apple Inc.",
		"version":       getStr(hw, "boot_rom_version"),
		"system_serial": getStr(hw, "serial_number"),
	}
	if uuid := getStr(hw, "platform_UUID"); uuid != "" {
		rec["hardware_uuid"] = uuid
	}
	return []schema.Record{rec}, nil
}

type macVirtualizationCollector struct{}

func (macVirtualizationCollector) Name() string { return "virtualization" }
func (macVirtualizationCollector) Level() int   { return levelMinimal }
func (macVirtualizationCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	items, err := systemProfiler("SPHardwareDataType")
	if err != nil {
		return nil, err
	}
	model := strings.ToLower(getStr(items[0], "model_identifier") + " " + getStr(items[0], "model_name"))
	vm := "Physical"
	switch {
	case strings.Contains(model, "vmware"):
		vm = "VMware"
	case strings.Contains(model, "parallels"):
		vm = "Parallels"
	case strings.Contains(model, "virtualbox"):
		vm = "VirtualBox"
	case strings.Contains(model, "qemu") || strings.Contains(model, "utm"):
		vm = "QEMU"
	case strings.Contains(model, "virtual"):
		vm = "VirtualMachine"
	}
	return []schema.Record{{"key": "virtualization", "vm_system": vm, "physical": vm == "Physical"}}, nil
}

type macSoftwareCollector struct{}

func (macSoftwareCollector) Name() string { return "software" }
func (macSoftwareCollector) Level() int   { return levelQuick }
func (macSoftwareCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	items, err := systemProfiler("SPApplicationsDataType")
	if err != nil {
		return []schema.Record{}, nil
	}
	out := []schema.Record{}
	for _, app := range items {
		name := getStr(app, "_name")
		if name == "" {
			continue
		}
		version := getStr(app, "version")
		out = append(out, schema.Record{
			"key": "macapp|" + name + "|" + version, "name": name, "version": version,
			"vendor": getStr(app, "signed_by"), "install_location": getStr(app, "path"),
			"format": "app", "source": getStr(app, "obtained_from"), "scope": "machine",
		})
	}
	return out, nil
}

type macGraphicsCollector struct{}

func (macGraphicsCollector) Name() string { return "graphics" }
func (macGraphicsCollector) Level() int   { return levelQuick }
func (macGraphicsCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	items, err := systemProfiler("SPDisplaysDataType")
	if err != nil {
		return []schema.Record{}, nil
	}
	out := []schema.Record{}
	for i, gpu := range items {
		name := getStr(gpu, "_name")
		if name == "" {
			name = getStr(gpu, "sppci_model")
		}
		out = append(out, schema.Record{
			"key": "gpu:" + strconv.Itoa(i), "name": name, "vendor": getStr(gpu, "spdisplays_vendor"),
			"driver_version": getStr(gpu, "spdisplays_gmux_version"),
		})
	}
	return out, nil
}

type macTPMCollector struct{}

func (macTPMCollector) Name() string { return "tpm" }
func (macTPMCollector) Level() int   { return levelQuick }
func (macTPMCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	items, err := systemProfiler("SPiBridgeDataType")
	if err != nil || len(items) == 0 {
		return []schema.Record{}, nil
	}
	rec := schema.Record{"key": "tpm", "present": true, "source": "ibridge"}
	for _, key := range []string{"ibridge_model", "ibridge_firmware_version", "ibridge_boot_uuid"} {
		if v := getStr(items[0], key); v != "" {
			rec[strings.TrimPrefix(key, "ibridge_")] = v
		}
	}
	return []schema.Record{rec}, nil
}

type macLocalUserCollector struct{}

func (macLocalUserCollector) Name() string { return "local_users" }
func (macLocalUserCollector) Level() int   { return levelQuick }
func (macLocalUserCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	out := []schema.Record{}
	if raw, err := runCommand("dscl", ".", "-list", "/Users", "UniqueID"); err == nil {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name, uid := fields[0], fields[1]
			if strings.HasPrefix(name, "_") {
				continue
			}
			out = append(out, schema.Record{
				"key": "user:" + uid, "name": name, "uid": uid, "account_type": "local",
				"system_account": len(uid) > 0 && uid[0] < '5',
			})
		}
		return out, nil
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return out, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		out = append(out, schema.Record{
			"key": "user:" + parts[2], "name": parts[0], "uid": parts[2], "gid": parts[3],
			"full_name": parts[4], "home": parts[5], "shell": parts[6], "account_type": "local",
		})
	}
	return out, sc.Err()
}

type macListeningPortCollector struct{}

func (macListeningPortCollector) Name() string { return "listening_ports" }
func (macListeningPortCollector) Level() int   { return levelFull }
func (macListeningPortCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	raw, err := runCommand("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if err != nil {
		return []schema.Record{}, nil
	}
	out := []schema.Record{}
	lines := strings.Split(raw, "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		name := fields[len(fields)-1]
		idx := strings.LastIndex(name, ":")
		if idx < 0 {
			continue
		}
		addr := name[:idx]
		port, err := strconv.Atoi(name[idx+1:])
		if err != nil || port < 1 {
			continue
		}
		family := "ipv4"
		if strings.Contains(addr, ":") {
			family = "ipv6"
		}
		out = append(out, schema.Record{
			"key":      "tcp|" + family + "|" + addr + "|" + strconv.Itoa(port),
			"protocol": "tcp", "address": addr, "port": port, "family": family,
			"process": fields[0], "pid": fields[1],
		})
	}
	return out, nil
}
