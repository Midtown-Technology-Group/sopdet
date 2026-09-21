// Package progress defines the event stream shared by the terminal reporter
// and the local web UI. Events are intentionally presentation-agnostic: the
// collector emits them, sinks decide how to render them.
package progress

import "time"

// Event kinds emitted during a run.
const (
	KindStart   = "start"   // run begins; Data carries host/profile
	KindPlan    = "plan"    // Total collectors will run
	KindEntity  = "entity"  // one collector finished (or failed)
	KindBudget  = "budget"  // payload size budgeting trimmed collections
	KindDeliver = "deliver" // delivery attempt finished
	KindDone    = "done"    // run complete; Data carries the summary
	KindError   = "error"   // fatal error
)

// Event is one step of a run, rendered by any number of sinks.
type Event struct {
	TS      int64          `json:"ts"`                // unix milliseconds
	Kind    string         `json:"kind"`              // one of the Kind* constants
	Stage   string         `json:"stage,omitempty"`   // coarse phase label
	Entity  string         `json:"entity,omitempty"`  // entity name for KindEntity
	Level   int            `json:"level,omitempty"`   // collector depth (0 = base)
	OK      *bool          `json:"ok,omitempty"`      // collector/sink success flag
	Count   int            `json:"count,omitempty"`   // records collected
	Ms      int64          `json:"ms,omitempty"`      // duration milliseconds
	Index   int            `json:"index,omitempty"`   // 1-based position in the plan
	Total   int            `json:"total,omitempty"`   // planned collector count
	Message string         `json:"message,omitempty"` // human-readable detail
	Data    map[string]any `json:"data,omitempty"`    // kind-specific payload
}

// Sink consumes events. Implementations must be safe to call from the
// collection goroutine; Emit must not block indefinitely.
type Sink interface {
	Emit(Event)
}

// Reporter stamps and forwards events to a function. A nil Reporter is valid
// and silently drops events, so callers never need nil checks.
type Reporter struct {
	fn func(Event)
}

// New builds a Reporter from a callback. A nil callback yields a no-op.
func New(fn func(Event)) *Reporter { return &Reporter{fn: fn} }

// Emit forwards e, filling in TS when unset.
func (r *Reporter) Emit(e Event) {
	if r == nil || r.fn == nil {
		return
	}
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	r.fn(e)
}

// Multi fans one event out to every sink, skipping nils.
func Multi(sinks ...Sink) *Reporter {
	kept := make([]Sink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			kept = append(kept, s)
		}
	}
	return New(func(e Event) {
		for _, s := range kept {
			s.Emit(e)
		}
	})
}

// Bool returns a pointer to b, for Event.OK.
func Bool(b bool) *bool { return &b }
