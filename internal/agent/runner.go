package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// LogEntry is one fenced log chunk produced by a job run. Seq starts at 1
// and is globally monotonic per Run call (stdout and stderr share one
// counter) — the idempotency key the platform freezes for
// POST /api/device/jobs/{id}/logs (M0 protocol).
type LogEntry struct {
	Seq    int
	Stream string // "stdout" | "stderr"
	Text   string
	TS     time.Time
}

// RunRequest describes one ad-hoc PowerShell job execution.
type RunRequest struct {
	JobID          string
	ScriptContent  string
	WorkDir        string
	Timeout        time.Duration
	MaxOutputBytes int64
}

// RunOutcome is the terminal local result of a run.
type RunOutcome struct {
	// ExitCode is the process exit code; -1 when no exit code was observed
	// (spawn failure, killed before exit).
	ExitCode int
	// TimedOut is true when the agent enforced the job timeout and killed
	// the process tree.
	TimedOut bool
	// Cancelled is true when the caller's context was cancelled (shutdown).
	Cancelled bool
	// Truncated is true when output hit MaxOutputBytes and was cut off.
	Truncated bool
	// Duration is spawn-to-wait wall time.
	Duration time.Duration
	// BytesObserved counts accepted output bytes (<= MaxOutputBytes).
	BytesObserved int64
}

// NotifyFunc reports that a real process has spawned. It runs exactly once,
// after a successful cmd.Start and before any log entry is emitted
// (feedback #1: the platform may only treat the job as `running` once spawn
// is real). A non-nil error aborts the run: the process tree is killed and
// no logs are emitted.
type NotifyFunc func() error

// LogFunc receives batches of log entries in seq order.
type LogFunc func(entries []LogEntry)

// Runner executes ad-hoc PowerShell jobs. It has no network dependencies:
// callers wire NotifyRunning/EmitLogs to the Bifrost HTTP protocol (M3.2).
type Runner struct {
	// PowerShellPath overrides the interpreter. Empty means the platform
	// default (powershell.exe on Windows).
	PowerShellPath string
	// BatchInterval is the max time a partial log buffer is held before
	// emission (default 500ms).
	BatchInterval time.Duration
	// BatchBytes is the max buffered bytes before emission (default 32KiB).
	BatchBytes int
}

// Defaults match the M0/M3 freeze (~500 ms or 32 KiB log batches).
const (
	DefaultBatchInterval = 500 * time.Millisecond
	DefaultBatchBytes    = 32 * 1024
	// utf8BOM keeps Windows PowerShell 5.1 from misreading non-ASCII scripts.
	utf8BOM = "\xEF\xBB\xBF"
)

// runState is shared by both stream pumps: one seq counter, one byte budget.
type runState struct {
	seqMu sync.Mutex
	seq   int

	budget outputBudget
	onLogs LogFunc
}

func (s *runState) nextSeq() int {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.seq++
	return s.seq
}

func (s *runState) emit(stream, text string) {
	if text == "" {
		return
	}
	if s.onLogs == nil {
		return
	}
	s.onLogs([]LogEntry{{
		Seq:    s.nextSeq(),
		Stream: stream,
		Text:   text,
		TS:     time.Now().UTC(),
	}})
}

// outputBudget is the shared combined stdout+stderr byte cap for one run.
type outputBudget struct {
	mu        sync.Mutex
	max       int64
	observed  int64
	truncated bool
}

// take returns the allowed prefix of chunk and records consumption.
func (b *outputBudget) take(chunk []byte) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.observed >= b.max {
		b.truncated = true
		return nil
	}
	room := b.max - b.observed
	if int64(len(chunk)) > room {
		b.observed = b.max
		b.truncated = true
		return chunk[:room]
	}
	b.observed += int64(len(chunk))
	return chunk
}

func (b *outputBudget) stats() (int64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.observed, b.truncated
}

// streamPump buffers one stream and flushes on size or interval.
type streamPump struct {
	stream   string
	interval time.Duration
	maxBuf   int
	state    *runState

	mu      sync.Mutex
	pending []byte
}

func (p *streamPump) add(chunk []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	allowed := p.state.budget.take(chunk)
	if len(allowed) > 0 {
		p.pending = append(p.pending, allowed...)
	}
	if len(p.pending) >= p.maxBuf {
		p.flushLocked()
	}
}

func (p *streamPump) flushLocked() {
	if len(p.pending) == 0 {
		return
	}
	text := string(p.pending)
	p.pending = p.pending[:0]
	p.state.emit(p.stream, text)
}

func (p *streamPump) flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flushLocked()
}

// ticker flushes partial buffers so silent-but-alive processes still emit
// on the batch interval.
func (p *streamPump) ticker(stop <-chan struct{}) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			p.flush()
		}
	}
}

// Run writes the script to a temp file, spawns the interpreter, notifies
// "running" exactly once after a real spawn, streams batched logs, and
// enforces Timeout + MaxOutputBytes. The temp file is always removed.
func (r *Runner) Run(
	ctx context.Context,
	req RunRequest,
	onStart NotifyFunc,
	onLogs LogFunc,
) (RunOutcome, error) {
	start := time.Now()
	fail := func(err error) (RunOutcome, error) {
		return RunOutcome{ExitCode: -1, Duration: time.Since(start)}, err
	}

	batchInterval := r.BatchInterval
	if batchInterval <= 0 {
		batchInterval = DefaultBatchInterval
	}
	batchBytes := r.BatchBytes
	if batchBytes <= 0 {
		batchBytes = DefaultBatchBytes
	}
	maxOutput := req.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = 1 << 20
	}
	if req.Timeout <= 0 {
		req.Timeout = 120 * time.Second
	}

	scriptPath, err := writeTempScript(req.WorkDir, req.ScriptContent)
	if err != nil {
		return fail(err)
	}
	defer os.Remove(scriptPath)

	powerShell := r.PowerShellPath
	if powerShell == "" {
		powerShell = defaultPowerShellPath()
	}
	if _, err := exec.LookPath(powerShell); err != nil {
		return fail(fmt.Errorf("powershell not found (%s): %w", powerShell, err))
	}

	runCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	cmd := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-File", scriptPath)
	configureProc(cmd)

	// Explicit OS pipes: cmd.Stdout=*os.File passes the fd straight through,
	// so cmd.Wait never races our readers or discards the final writes.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return fail(err)
	}
	defer stdoutR.Close()
	defer stderrR.Close()
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		stdoutW.Close()
		stderrW.Close()
		return fail(err)
	}
	// Drop parent copies so readers see EOF once every child-side fd is gone.
	stdoutW.Close()
	stderrW.Close()

	// Spawn is real — report `running` before any output is emitted.
	if onStart != nil {
		if err := onStart(); err != nil {
			killTree(cmd)
			_ = cmd.Wait()
			return fail(fmt.Errorf("running notification rejected: %w", err))
		}
	}

	state := &runState{budget: outputBudget{max: maxOutput}, onLogs: onLogs}
	stop := make(chan struct{})
	outPump := &streamPump{
		stream: "stdout", interval: batchInterval, maxBuf: batchBytes, state: state,
	}
	errPump := &streamPump{
		stream: "stderr", interval: batchInterval, maxBuf: batchBytes, state: state,
	}
	go outPump.ticker(stop)
	go errPump.ticker(stop)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pumpReader(outPump, stdoutR)
	}()
	go func() {
		defer wg.Done()
		pumpReader(errPump, stderrR)
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-runCtx.Done():
		// Timeout or caller cancellation: kill the tree so Wait returns and
		// every pipe write-end is released.
		killTree(cmd)
		waitErr = <-waitDone
	}
	// Sweep grandchildren that outlived the direct child and still hold
	// pipe write-ends (otherwise the pumps never see EOF).
	killTree(cmd)
	wg.Wait()
	close(stop)
	outPump.flush()
	errPump.flush()

	observed, truncated := state.budget.stats()
	outcome := RunOutcome{
		Truncated:     truncated,
		BytesObserved: observed,
		Duration:      time.Since(start),
	}

	switch {
	case runCtx.Err() == context.DeadlineExceeded:
		outcome.TimedOut = true
		outcome.ExitCode = -1
	case ctx.Err() == context.Canceled:
		outcome.Cancelled = true
		outcome.ExitCode = -1
	case waitErr != nil:
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			outcome.ExitCode = exitErr.ExitCode()
		} else {
			outcome.ExitCode = -1
		}
	default:
		outcome.ExitCode = 0
	}
	return outcome, nil
}

// pumpReader copies until EOF, flushing on size thresholds; the ticker
// handles time-based flushes while the reader blocks.
func pumpReader(p *streamPump, rd io.Reader) {
	reader := bufio.NewReaderSize(rd, 16*1024)
	buf := make([]byte, 8*1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			p.add(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func writeTempScript(workDir, content string) (string, error) {
	dir := workDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "sopdet-job-*.ps1")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.WriteString(utf8BOM + content); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	return filepath.Clean(path), nil
}
