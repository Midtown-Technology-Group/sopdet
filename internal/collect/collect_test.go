package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

type partialCollector struct{}

func (partialCollector) Name() string { return "partial" }
func (partialCollector) Level() int   { return levelMinimal }
func (partialCollector) Collect(context.Context, *Session) ([]schema.Record, error) {
	return []schema.Record{{"key": "retained", "value": "observed"}}, errors.New("access denied reading secondary source")
}

func TestRunPlanRetainsPartialRecordsAndReportsGatedError(t *testing.T) {
	entities, entityErrors := runPlan(context.Background(), []Collector{partialCollector{}}, &Session{})
	if entities["partial"] == nil || entities["partial"].Count != 1 {
		t.Fatalf("partial records were discarded: %#v", entities["partial"])
	}
	err, ok := entityErrors["partial"]
	if !ok || !err.Gated || err.Error == "" {
		t.Fatalf("partial error was not surfaced as gated: %#v", entityErrors)
	}
}

func TestRunPlanDoesNotPublishEmptyFailedEntity(t *testing.T) {
	collector := failingCollector{err: errors.New("query failed")}
	entities, entityErrors := runPlan(context.Background(), []Collector{collector}, &Session{})
	if _, ok := entities[collector.Name()]; ok {
		t.Fatal("empty failed entity was published")
	}
	if _, ok := entityErrors[collector.Name()]; !ok {
		t.Fatal("collector failure was not reported")
	}
}

func TestLooksGatedRecognizesPlatformAccessErrors(t *testing.T) {
	for _, message := range []string{"Access is denied", "permission denied", "operation not permitted", "requires elevation", "HRESULT 0x80070005"} {
		if !looksGated(message) {
			t.Errorf("access failure was not gated: %q", message)
		}
	}
	if looksGated("command not found") {
		t.Fatal("ordinary execution failure was incorrectly gated")
	}
}

type failingCollector struct{ err error }

func (f failingCollector) Name() string { return "failed" }
func (f failingCollector) Level() int   { return levelMinimal }
func (f failingCollector) Collect(context.Context, *Session) ([]schema.Record, error) {
	return nil, f.err
}
