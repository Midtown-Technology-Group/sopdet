//go:build darwin

package collect

import (
	"context"
	"errors"
	"testing"
)

func TestDarwinCollectorsSurfaceCommandErrors(t *testing.T) {
	original := collectorRunCommand
	t.Cleanup(func() { collectorRunCommand = original })
	denied := errors.New("access denied")
	collectorRunCommand = func(string, ...string) (string, error) { return "", denied }

	profilerCollectors := []Collector{
		macHardwareCollector{}, macBiosCollector{}, macVirtualizationCollector{},
		macSoftwareCollector{}, macGraphicsCollector{}, macTPMCollector{},
	}
	for _, collector := range profilerCollectors {
		if _, err := collector.Collect(context.Background(), nil); !errors.Is(err, denied) {
			t.Fatalf("%s command error was suppressed: %v", collector.Name(), err)
		}
	}
	if _, err := (macListeningPortCollector{}).Collect(context.Background(), nil); !errors.Is(err, denied) {
		t.Fatalf("listening-port command error was suppressed: %v", err)
	}
	records, err := (macLocalUserCollector{}).Collect(context.Background(), nil)
	if len(records) == 0 || !errors.Is(err, denied) {
		t.Fatalf("local-user fallback did not retain records and dscl error: records=%d err=%v", len(records), err)
	}
}
