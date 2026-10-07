package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Serve orchestration (M3.5 #842): max ONE concurrent job, WS hint OR
// periodic claim poll, heartbeat ~30s, and the frozen shutdown/fence rules:
//
//   - no local re-run after any uncertain outcome — fenced rejections are
//     accepted (the server owns the verdict; `lost` needs an explicit new
//     job);
//   - graceful shutdown while a job runs leaves it `running` for the
//     server's lost policy (we kill our local process tree and post
//     nothing);
//   - a cooperative cancel (heartbeat flag) kills the local tree and posts
//     `cancelled`.
type Serve struct {
	Config         ServeConfig
	Client         *Client
	Runner         *Runner
	Hints          *WSHintClient
	Wake           chan struct{}
	HeartbeatEvery time.Duration
	// EnableHints gates the WebSocket hint goroutine (Run). It mirrors
	// ServeConfig.EnableHints: true by default, false when the M6.3
	// poll-only drill sets SOPDET_DISABLE_HINTS.
	EnableHints bool
	// Logf receives operator-visible serve diagnostics (nil: stderr). Used
	// for report-path events that must never be silent, such as a terminal
	// report the server refused (bifrost#951 follow-up).
	Logf func(format string, a ...any)

	mu        sync.Mutex
	curCancel context.CancelFunc
}

// NewServe builds the orchestration around an already-prepared identity.
// The heartbeat's agent_version comes from cfg.AgentVersion (main.Version),
// and cfg.EnableHints decides whether the WebSocket hint channel runs at all
// (SOPDET_DISABLE_HINTS resolves it false for the M6.3 poll-only drill).
func NewServe(cfg ServeConfig, state DeviceState) (*Serve, error) {
	spoolDir := filepath.Join(filepath.Dir(cfg.StatePath), "spool")
	client := NewClient(cfg.BifrostURL, state.DeviceKey, spoolDir)
	client.AgentVersion = cfg.AgentVersion
	runner := &Runner{} // WorkDir is per-job (RunRequest.WorkDir)
	s := &Serve{
		Config:         cfg,
		Client:         client,
		Runner:         runner,
		Wake:           make(chan struct{}, 1),
		HeartbeatEvery: 30 * time.Second,
		EnableHints:    cfg.EnableHints,
	}
	hints, err := NewWSHintClient(client, func() {
		select {
		case s.Wake <- struct{}{}:
		default: // a pending wake already exists — claims are idempotent
		}
	})
	if err != nil {
		return nil, err
	}
	s.Hints = hints
	return s, nil
}

func (s *Serve) setCurrent(cancel context.CancelFunc) {
	s.mu.Lock()
	s.curCancel = cancel
	s.mu.Unlock()
}

func (s *Serve) clearCurrent() {
	s.mu.Lock()
	s.curCancel = nil
	s.mu.Unlock()
}

// cancelCurrent triggers the cooperative cancel of the running job (no-op
// when idle). Safe to call from the heartbeat goroutine.
func (s *Serve) cancelCurrent() {
	s.mu.Lock()
	cancel := s.curCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// logf emits a serve diagnostic without ever panicking on a nil Logf.
func (s *Serve) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
		return
	}
	fmt.Fprintf(os.Stderr, "serve: "+format+"\n", a...)
}

// reportTerminal posts the job's terminal result. A fenced rejection is the
// server's accepted verdict (already terminal), not a loss; every other
// failure must at least be visible in the agent log — a silently dropped
// terminal report leaves the job `running` until the server watchdog
// reaps it (bifrost#951).
func (s *Serve) reportTerminal(ctx context.Context, job *ClaimedJob, payload ResultPayload) {
	payload.ClaimToken = job.ClaimToken
	if err := s.Client.ReportResult(ctx, job.JobID, payload); err != nil &&
		!errors.Is(err, ErrFenced) {
		s.logf("terminal report for job %s failed: %v", job.JobID, err)
	}
}

// Run serves until ctx is cancelled. Claim attempts start immediately, then
// follow the server-provided poll hint (WS hints shorten latency further).
func (s *Serve) Run(ctx context.Context) error {
	if removed, err := s.Client.SweepSpool(); err == nil && removed > 0 {
		fmt.Fprintf(os.Stderr, "serve: swept %d stale spool files\n", removed)
	}
	// Stale per-job script staging (crash/kill leftovers) is swept once
	// at startup, before this process stages any script, so the sweep
	// can never meet this agent's own active file; recent foreign files
	// are preserved by the 24h age bound (see SweepStaleScripts).
	s.sweepStaleJobScripts()
	if s.EnableHints && s.Hints != nil {
		go s.Hints.Run(ctx)
	}
	go s.heartbeatLoop(ctx)

	poll := s.Config.PollInterval
	if poll <= 0 {
		poll = DefaultServePollInterval
	}
	pollTimer := time.NewTimer(0) // claim right away
	defer pollTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.Wake:
		case <-pollTimer.C:
		}

		if ctx.Err() != nil {
			return nil
		}
		job, err := s.Client.Claim(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Claim already retried transient errors; fall back to polling.
			pollTimer.Reset(poll)
			continue
		}
		if job == nil {
			pollTimer.Reset(poll)
			continue
		}

		s.process(ctx, job)
		pollTimer.Reset(0) // more work may be waiting after a terminal
	}
}

func (s *Serve) sweepStaleJobScripts() {
	if s.Config.WorkDir == "" {
		return
	}
	removed, err := SweepStaleScripts(s.Config.WorkDir)
	if removed > 0 {
		s.logf("swept %d stale job scripts", removed)
	}
	if err != nil {
		s.logf("stale job script sweep incomplete: %v", err)
	}
}

// heartbeatLoop keeps activity fresh, tracks the poll hint, drains the
// spool, and observes cooperative cancels for the running job.
func (s *Serve) heartbeatLoop(ctx context.Context) {
	every := s.HeartbeatEvery
	if every <= 0 {
		every = 30 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hb, err := s.Client.Heartbeat(ctx)
			if err != nil {
				continue // transient; claim poll still works independently
			}
			// Best-effort spool drain keeps observation fresh after outages.
			_, _ = s.Client.DrainSpool(ctx)
			if hb.CancelRequested {
				s.cancelCurrent()
			}
		}
	}
}

// process runs one claimed job to a terminal report (or abandons it for the
// server's lost policy on shutdown). Max one runs at a time: the claim loop
// is synchronous.
func (s *Serve) process(serveCtx context.Context, job *ClaimedJob) {
	jobCtx, jobCancel := context.WithCancel(serveCtx)
	s.setCurrent(jobCancel)
	defer func() {
		s.clearCurrent()
		jobCancel()
	}()

	outcome, runErr := s.Runner.Run(
		jobCtx,
		RunRequest{
			JobID:          job.JobID,
			ScriptContent:  job.ScriptContent,
			WorkDir:        s.Config.WorkDir,
			Timeout:        time.Duration(job.TimeoutSeconds) * time.Second,
			MaxOutputBytes: job.MaxOutputBytes,
		},
		func() error {
			return s.Client.ReportRunning(serveCtx, job.JobID, job.ClaimToken)
		},
		func(entries []LogEntry) {
			batch := make([]LogBatchEntry, 0, len(entries))
			for _, e := range entries {
				batch = append(batch, LogBatchEntry{
					Seq:    e.Seq,
					Stream: e.Stream,
					Text:   e.Text,
					TS:     e.TS,
				})
			}
			// PostLogs spools transient failures itself; a fenced rejection
			// means the server already owns the outcome — swallow it here
			// (the result post below will be fenced and accepted too).
			_ = s.Client.PostLogs(serveCtx, job.JobID, job.ClaimToken, batch)
		},
	)

	if runErr != nil {
		if errors.Is(runErr, ErrRunningRejected) {
			// Fence at spawn report: the server owns the outcome
			// (terminal/lost). Never re-run, never post.
			s.logf("spawn report rejected for job %s; leaving the outcome to the server: %v",
				job.JobID, runErr)
			return
		}
		// Preparation/spawn failure: the script never started, so a
		// `failed` report is honest and safe.
		s.reportTerminal(serveCtx, job, ResultPayload{
			Status: "failed",
			Error:  runErr.Error(),
		})
		return
	}

	// Shutdown while running: abandon locally — the tree was killed via
	// jobCtx; leave `running` for the server's lost policy (M0). No post,
	// no rerun.
	if serveCtx.Err() != nil {
		return
	}

	// Cooperative cancel: jobCtx was cancelled while serve lives — the
	// runner killed the tree on the heartbeat flag; report cancelled.
	if jobCtx.Err() != nil {
		s.reportTerminal(serveCtx, job, ResultPayload{
			Status: "cancelled",
			Error:  "cooperative cancel observed via heartbeat",
		})
		return
	}

	payload := ResultPayload{
		Truncated: outcome.Truncated,
	}
	ms := outcome.Duration.Milliseconds()
	payload.DurationMS = &ms

	switch {
	case outcome.TimedOut:
		payload.Status = "timeout"
		payload.Error = fmt.Sprintf(
			"killed after job timeout (%s)", time.Duration(job.TimeoutSeconds)*time.Second,
		)
	case outcome.ExitCode == 0:
		payload.Status = "succeeded"
	default:
		payload.Status = "failed"
		code := outcome.ExitCode
		payload.ExitCode = &code
	}

	// ReportResult spools transient failures; a fenced rejection is accepted
	// (server already terminal) — either way this job ends here, and any
	// non-fenced rejection is surfaced by reportTerminal instead of being
	// dropped silently (bifrost#951).
	s.reportTerminal(serveCtx, job, payload)
}
