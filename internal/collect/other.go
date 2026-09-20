//go:build !windows

package collect

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// PlatformIdentity reports elevation on Unix-like systems. Hardware UUID is
// not read here; Linux/DMI and macOS IOKit collectors can add it later.
func PlatformIdentity() (machineGUID, hardwareUUID *string, elevated bool) {
	return nil, nil, os.Geteuid() == 0
}

// PlatformCollectors returns OS-specific collectors.
func PlatformCollectors(_ *Session) []Collector {
	if runtime.GOOS == "linux" {
		return []Collector{dpkgSoftwareCollector{}}
	}
	return nil
}

type dpkgSoftwareCollector struct{}

func (dpkgSoftwareCollector) Name() string { return "software" }
func (dpkgSoftwareCollector) Level() int   { return levelQuick }

func (dpkgSoftwareCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := []schema.Record{}
	fields := map[string]string{}
	flush := func() {
		if fields["Package"] == "" || !strings.Contains(fields["Status"], "installed") {
			fields = map[string]string{}
			return
		}
		rec := schema.Record{
			"key":          "deb|" + fields["Package"] + "|" + fields["Version"],
			"name":         fields["Package"],
			"version":      fields["Version"],
			"vendor":       fields["Maintainer"],
			"architecture": fields["Architecture"],
			"format":       "deb",
			"source":       "dpkg",
			"scope":        "machine",
		}
		out = append(out, rec)
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
