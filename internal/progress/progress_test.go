package progress

import "testing"

func TestNilReporterIsNoop(t *testing.T) {
	var r *Reporter
	r.Emit(Event{Kind: KindStart}) // must not panic
	if r := New(nil); r != nil {
		r.Emit(Event{Kind: KindStart})
	}
}

func TestEmitStampsTimestamp(t *testing.T) {
	var got Event
	New(func(e Event) { got = e }).Emit(Event{Kind: KindEntity})
	if got.TS == 0 {
		t.Fatal("expected TS to be stamped")
	}
}

func TestEmitPreservesTimestamp(t *testing.T) {
	var got Event
	New(func(e Event) { got = e }).Emit(Event{Kind: KindEntity, TS: 12345})
	if got.TS != 12345 {
		t.Fatalf("TS = %d, want 12345", got.TS)
	}
}

func TestMultiFansOutAndSkipsNil(t *testing.T) {
	var a, b int
	rep := Multi(
		New(func(Event) { a++ }),
		nil,
		New(func(Event) { b++ }),
	)
	rep.Emit(Event{Kind: KindPlan})
	if a != 1 || b != 1 {
		t.Fatalf("a=%d b=%d, want 1/1", a, b)
	}
}

func TestBool(t *testing.T) {
	if p := Bool(true); p == nil || !*p {
		t.Fatal("Bool(true) mismatch")
	}
	if p := Bool(false); p == nil || *p {
		t.Fatal("Bool(false) mismatch")
	}
}
