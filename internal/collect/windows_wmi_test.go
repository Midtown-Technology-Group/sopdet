//go:build windows

package collect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestWindowsCollectorsSurfaceCommandFailures(t *testing.T) {
	original := collectorAssessCombined
	t.Cleanup(func() { collectorAssessCombined = original })
	denied := errors.New("access denied")

	collectorAssessCombined = func(context.Context, string, ...string) (string, error) {
		return "denied output", denied
	}
	if _, err := enrichDefenderStatus(context.Background(), nil); !errors.Is(err, denied) {
		t.Fatalf("Defender command error was suppressed: %v", err)
	}
	if _, err := (winAppxCollector{}).Collect(context.Background(), nil); !errors.Is(err, denied) {
		t.Fatalf("AppX command error was suppressed: %v", err)
	}
	if _, err := (winThreatCollector{}).Collect(context.Background(), nil); !errors.Is(err, denied) {
		t.Fatalf("threat command error was suppressed: %v", err)
	}

	collectorAssessCombined = func(context.Context, string, ...string) (string, error) {
		return "not-json", nil
	}
	if _, err := enrichDefenderStatus(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "parse Defender") {
		t.Fatalf("Defender parse error was suppressed: %v", err)
	}
	if _, err := (winAppxCollector{}).Collect(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "parse AppX") {
		t.Fatalf("AppX parse error was suppressed: %v", err)
	}
	if _, err := (winThreatCollector{}).Collect(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "parse Defender threat") {
		t.Fatalf("threat parse error was suppressed: %v", err)
	}

	collectorAssessCombined = func(context.Context, string, ...string) (string, error) {
		return "", nil
	}
	if _, err := enrichDefenderStatus(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "empty output") {
		t.Fatalf("empty Defender output was suppressed: %v", err)
	}
}

func TestWindowsCollectorsRetainPartialRecordsWithQueryErrors(t *testing.T) {
	originalQuery := collectorWMIQuery
	originalNamespace := collectorWMIQueryNamespace
	t.Cleanup(func() {
		collectorWMIQuery = originalQuery
		collectorWMIQueryNamespace = originalNamespace
	})
	denied := errors.New("access denied")

	calls := 0
	collectorWMIQuery = func(string, interface{}, ...interface{}) error {
		calls++
		if calls == 1 {
			return nil
		}
		return denied
	}
	records, err := (winHardwareCollector{}).Collect(context.Background(), nil)
	if len(records) != 1 || !errors.Is(err, denied) {
		t.Fatalf("hardware partial result was not retained: records=%v err=%v", records, err)
	}

	collectorWMIQuery = func(string, interface{}, ...interface{}) error { return denied }
	records, err = (winBiosCollector{}).Collect(context.Background(), nil)
	if len(records) != 1 || !errors.Is(err, denied) {
		t.Fatalf("BIOS query errors were suppressed: records=%v err=%v", records, err)
	}

	collectorWMIQuery = func(string, interface{}, ...interface{}) error { return nil }
	collectorWMIQueryNamespace = func(string, interface{}, string) error { return denied }
	records, err = (winVolumesCollector{}).Collect(context.Background(), nil)
	if len(records) != 0 || !errors.Is(err, denied) {
		t.Fatalf("BitLocker query error was suppressed: records=%v err=%v", records, err)
	}
}

func TestWindowsRegistryCollectorsSurfaceOpenErrors(t *testing.T) {
	original := collectorRegistryOpenKey
	t.Cleanup(func() { collectorRegistryOpenKey = original })
	denied := errors.New("access denied")
	collectorRegistryOpenKey = func(registry.Key, string, uint32) (registry.Key, error) {
		return 0, denied
	}

	if _, err := (winSecureBootCollector{}).Collect(context.Background(), nil); !errors.Is(err, denied) {
		t.Fatalf("Secure Boot registry error was suppressed: %v", err)
	}
	records, err := (winFirewallCollector{}).Collect(context.Background(), nil)
	if len(records) != 0 || !errors.Is(err, denied) {
		t.Fatalf("firewall registry errors were suppressed: records=%v err=%v", records, err)
	}
}
