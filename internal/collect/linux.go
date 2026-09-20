//go:build linux

package collect

import (
	"bufio"
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// PlatformIdentity reports elevation on Linux. Machine/hardware identity is
// resolved from /sys/class/dmi/id when readable.
func PlatformIdentity() (machineGUID, hardwareUUID *string, elevated bool) {
	if v := readTrim("/sys/class/dmi/id/product_uuid"); v != "" {
		hardwareUUID = &v
	}
	return nil, hardwareUUID, os.Geteuid() == 0
}

// PlatformCollectors returns the Linux-specific collector set.
func PlatformCollectors(_ *Session) []Collector {
	return []Collector{
		linuxBiosCollector{},
		linuxVirtualizationCollector{},
		linuxSecureBootCollector{},
		linuxTPMCollector{},
		linuxLocalUserCollector{},
		linuxListeningPortCollector{},
		linuxSoftwareCollector{},
	}
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

type linuxBiosCollector struct{}

func (linuxBiosCollector) Name() string { return "bios" }
func (linuxBiosCollector) Level() int   { return levelQuick }
func (linuxBiosCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{"key": "bios", "source": "dmi"}
	set := func(field, file string) {
		if v := readTrim("/sys/class/dmi/id/" + file); v != "" {
			rec[field] = v
		}
	}
	set("manufacturer", "sys_vendor")
	set("name", "product_name")
	set("version", "bios_version")
	set("release_date", "bios_date")
	set("system_serial", "product_serial")
	set("enclosure_serial", "chassis_serial")
	rec["board_manufacturer"] = readTrim("/sys/class/dmi/id/board_vendor")
	rec["board_product"] = readTrim("/sys/class/dmi/id/board_name")
	rec["board_serial"] = readTrim("/sys/class/dmi/id/board_serial")
	rec["sku_number"] = readTrim("/sys/class/dmi/id/product_sku")
	rec["chassis_types"] = readTrim("/sys/class/dmi/id/chassis_type")
	if len(rec) <= 2 {
		return []schema.Record{}, nil
	}
	return []schema.Record{rec}, nil
}

type linuxVirtualizationCollector struct{}

func (linuxVirtualizationCollector) Name() string { return "virtualization" }
func (linuxVirtualizationCollector) Level() int   { return levelMinimal }
func (linuxVirtualizationCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	vendor := readTrim("/sys/class/dmi/id/sys_vendor")
	product := readTrim("/sys/class/dmi/id/product_name")
	cpuinfo := readTrim("/proc/cpuinfo")
	vm := vmSystemFrom(vendor, product, strings.Contains(cpuinfo, "hypervisor"))
	return []schema.Record{{"key": "virtualization", "vm_system": vm, "physical": vm == "Physical"}}, nil
}

type linuxSecureBootCollector struct{}

func (linuxSecureBootCollector) Name() string { return "secureboot" }
func (linuxSecureBootCollector) Level() int   { return levelMinimal }
func (linuxSecureBootCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil || len(data) < 5 {
		return []schema.Record{}, nil
	}
	value := int(data[len(data)-1])
	return []schema.Record{{"key": "secureboot", "secure_boot": value, "source": "efivar"}}, nil
}

type linuxTPMCollector struct{}

func (linuxTPMCollector) Name() string { return "tpm" }
func (linuxTPMCollector) Level() int   { return levelQuick }
func (linuxTPMCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	desc := readTrim("/sys/class/tpm/tpm0/device/description")
	version := readTrim("/sys/class/tpm/tpm0/tpm_version_major")
	if desc == "" && version == "" {
		return []schema.Record{}, nil
	}
	return []schema.Record{{"key": "tpm", "present": true, "manufacturer_version": desc, "spec_version": version, "source": "sysfs"}}, nil
}

type linuxLocalUserCollector struct{}

func (linuxLocalUserCollector) Name() string { return "local_users" }
func (linuxLocalUserCollector) Level() int   { return levelQuick }
func (linuxLocalUserCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []schema.Record{}
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

func hexIPv4(h string) string {
	if len(h) != 8 {
		return h
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return h
	}
	return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0]))
}

type linuxListeningPortCollector struct{}

func (linuxListeningPortCollector) Name() string { return "listening_ports" }
func (linuxListeningPortCollector) Level() int   { return levelFull }
func (linuxListeningPortCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	out := []schema.Record{}
	files := []struct {
		path string
		kind string
	}{
		{"/proc/net/tcp", "ipv4"},
		{"/proc/net/tcp6", "ipv6"},
		{"/proc/net/udp", "ipv4"},
		{"/proc/net/udp6", "ipv6"},
	}
	for _, file := range files {
		f, err := os.Open(file.path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			proto := "tcp"
			if strings.Contains(file.path, "udp") {
				proto = "udp"
			}
			if proto == "tcp" && fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			local := fields[1]
			idx := strings.LastIndex(local, ":")
			if idx < 0 {
				continue
			}
			port, err := strconv.ParseInt(local[idx+1:], 16, 32)
			if err != nil || port < 1 || port >= 49152 {
				continue
			}
			addr := local[:idx]
			resolved := addr
			if file.kind == "ipv4" {
				resolved = hexIPv4(addr)
			}
			out = append(out, schema.Record{
				"key":      proto + "|" + file.kind + "|" + resolved + "|" + strconv.Itoa(int(port)),
				"protocol": proto, "address": resolved, "port": port, "family": file.kind, "process": nil,
			})
		}
		f.Close()
	}
	return out, nil
}

type linuxSoftwareCollector struct{}

func (linuxSoftwareCollector) Name() string { return "software" }
func (linuxSoftwareCollector) Level() int   { return levelQuick }
func (linuxSoftwareCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	if recs, err := collectDpkg(); err == nil && len(recs) > 0 {
		return recs, nil
	}
	if recs, err := collectRPM(); err == nil && len(recs) > 0 {
		return recs, nil
	}
	if recs, err := collectPacman(); err == nil && len(recs) > 0 {
		return recs, nil
	}
	if recs, err := collectApk(); err == nil && len(recs) > 0 {
		return recs, nil
	}
	return []schema.Record{}, nil
}

func collectDpkg() ([]schema.Record, error) {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []schema.Record{}
	fields := map[string]string{}
	flush := func() {
		if fields["Package"] != "" && strings.Contains(fields["Status"], "installed") {
			out = append(out, schema.Record{
				"key": "deb|" + fields["Package"] + "|" + fields["Version"], "name": fields["Package"],
				"version": fields["Version"], "vendor": fields["Maintainer"], "architecture": fields["Architecture"],
				"format": "deb", "source": "dpkg", "scope": "machine",
			})
		}
		fields = map[string]string{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	flush()
	return out, sc.Err()
}

func collectRPM() ([]schema.Record, error) {
	out, err := runCommand("rpm", "-qa", "--qf", "%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{ARCH}\\n")
	if err != nil {
		return nil, err
	}
	recs := []schema.Record{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 4 || parts[0] == "" {
			continue
		}
		recs = append(recs, schema.Record{
			"key": "rpm|" + parts[0] + "|" + parts[1], "name": parts[0], "version": parts[1],
			"vendor": parts[2], "architecture": parts[3], "format": "rpm", "source": "rpm", "scope": "machine",
		})
	}
	return recs, nil
}

func collectPacman() ([]schema.Record, error) {
	entries, err := os.ReadDir("/var/lib/pacman/local")
	if err != nil {
		return nil, err
	}
	recs := []schema.Record{}
	for _, e := range entries {
		desc := readTrim("/var/lib/pacman/local/" + e.Name() + "/desc")
		if desc == "" {
			continue
		}
		name, version := "", ""
		lines := strings.Split(desc, "\n")
		for i, l := range lines {
			if l == "%NAME%" && i+1 < len(lines) {
				name = lines[i+1]
			}
			if (l == "%VERSION%" || l == "%BASE%") && i+1 < len(lines) && version == "" {
				version = lines[i+1]
			}
		}
		if name != "" {
			recs = append(recs, schema.Record{
				"key": "pacman|" + name + "|" + version, "name": name, "version": version,
				"format": "pkg", "source": "pacman", "scope": "machine",
			})
		}
	}
	return recs, nil
}

func collectApk() ([]schema.Record, error) {
	f, err := os.Open("/lib/apk/db/installed")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	recs := []schema.Record{}
	fields := map[string]string{}
	flush := func() {
		if fields["P"] != "" {
			recs = append(recs, schema.Record{
				"key": "apk|" + fields["P"] + "|" + fields["V"], "name": fields["P"], "version": fields["V"],
				"architecture": fields["A"], "format": "apk", "source": "apk", "scope": "machine",
			})
		}
		fields = map[string]string{}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = v
		}
	}
	flush()
	return recs, sc.Err()
}
