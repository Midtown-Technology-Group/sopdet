package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePowerShell writes an executable sh script used in place of
// powershell.exe. The runner invokes it with -NoProfile -NonInteractive
// -File <script>; the fake ignores those flags and follows its own body.
func fakePowerShell(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-powershell")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRequest(workDir, script string) RunRequest {
	return RunRequest{
		JobID:          "job-1",
		ScriptContent:  script,
		WorkDir:        workDir,
		Timeout:        5 * time.Second,
		MaxOutputBytes: 1 << 20,
	}
}

func TestRunnerSuccessReportsRunningBeforeLogs(t *testing.T) {
	fake := fakePowerShell(t, "echo hello\necho err >&2\nexit 3\n")
	work := t.TempDir()

	var mu sync.Mutex
	var events []string
	var entries []LogEntry

	outcome, err := (&Runner{PowerShellPath: fake, BatchInterval: 20 * time.Millisecond}).Run(
		context.Background(),
		testRequest(work, "# unused by fake"),
		func() error {
			mu.Lock()
			events = append(events, "running")
			mu.Unlock()
			return nil
		},
		func(batch []LogEntry) {
			mu.Lock()
			for range batch {
				events = append(events, "log")
			}
			entries = append(entries, batch...)
			mu.Unlock()
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if outcome.ExitCode != 3 {
		t.Errorf("exit = %d, want 3", outcome.ExitCode)
	}
	if outcome.TimedOut || outcome.Cancelled || outcome.Truncated {
		t.Errorf("unexpected flags: %+v", outcome)
	}
	if len(events) == 0 || events[0] != "running" {
		t.Errorf("running must be reported before any log, events=%v", events)
	}
	runningCount := 0
	for _, e := range events {
		if e == "running" {
			runningCount++
		}
	}
	if runningCount != 1 {
		t.Errorf("running notifications = %d, want 1", runningCount)
	}
	var sawStdout, sawStderr bool
	lastSeq := 0
	for _, e := range entries {
		if e.Seq <= lastSeq {
			t.Errorf("seq not monotonic: %d after %d", e.Seq, lastSeq)
		}
		lastSeq = e.Seq
		if e.Stream == "stdout" && strings.Contains(e.Text, "hello") {
			sawStdout = true
		}
		if e.Stream == "stderr" && strings.Contains(e.Text, "err") {
			sawStderr = true
		}
	}
	if !sawStdout || !sawStderr {
		t.Errorf("missing stream output: stdout=%v stderr=%v", sawStdout, sawStderr)
	}
	if len(entries) > 0 && entries[0].Seq != 1 {
		t.Errorf("first seq = %d, want 1", entries[0].Seq)
	}
}

func TestRunnerTimeoutKillsProcessTree(t *testing.T) {
	fake := fakePowerShell(t, "sleep 30\n")
	work := t.TempDir()

	start := time.Now()
	outcome, err := (&Runner{PowerShellPath: fake, BatchInterval: 20 * time.Millisecond}).Run(
		context.Background(),
		RunRequest{
			ScriptContent:  "x",
			WorkDir:        work,
			Timeout:        300 * time.Millisecond,
			MaxOutputBytes: 1 << 20,
		},
		nil,
		nil,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !outcome.TimedOut {
		t.Errorf("expected timeout, got %+v", outcome)
	}
	if outcome.Cancelled {
		t.Errorf("timeout must not be reported as cancelled")
	}
	if elapsed > 5*time.Second {
		t.Errorf("run took %v; process tree was not killed promptly", elapsed)
	}
}

func TestRunnerOutputCapEnforced(t *testing.T) {
	fake := fakePowerShell(t, "head -c 200000 /dev/zero | tr '\\0' 'a'\n")
	work := t.TempDir()

	var mu sync.Mutex
	var total int
	outcome, err := (&Runner{PowerShellPath: fake, BatchInterval: 20 * time.Millisecond, BatchBytes: 1024}).Run(
		context.Background(),
		RunRequest{
			ScriptContent:  "x",
			WorkDir:        work,
			Timeout:        5 * time.Second,
			MaxOutputBytes: 1000,
		},
		nil,
		func(batch []LogEntry) {
			mu.Lock()
			for _, e := range batch {
				total += len(e.Text)
			}
			mu.Unlock()
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !outcome.Truncated {
		t.Errorf("expected truncation")
	}
	if outcome.BytesObserved != 1000 {
		t.Errorf("BytesObserved = %d, want 1000", outcome.BytesObserved)
	}
	mu.Lock()
	defer mu.Unlock()
	if total > 1000 {
		t.Errorf("emitted %d bytes, cap is 1000", total)
	}
}

func TestRunnerNotifyFailureKillsWithoutLogs(t *testing.T) {
	fake := fakePowerShell(t, "echo should-not-appear\nsleep 30\n")
	work := t.TempDir()

	var logCalls int
	start := time.Now()
	_, err := (&Runner{PowerShellPath: fake, BatchInterval: 20 * time.Millisecond}).Run(
		context.Background(),
		testRequest(work, "x"),
		func() error { return errors.New("fence_violation") },
		func([]LogEntry) { logCalls++ },
	)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "fence_violation") {
		t.Fatalf("expected fence rejection error, got: %v", err)
	}
	if logCalls != 0 {
		t.Errorf("logs emitted after notify failure: %d calls", logCalls)
	}
	if elapsed > 5*time.Second {
		t.Errorf("process not killed promptly (%v)", elapsed)
	}
}

func TestRunnerRemovesTempScript(t *testing.T) {
	fake := fakePowerShell(t, "exit 0\n")
	work := t.TempDir()
	_, err := (&Runner{PowerShellPath: fake, BatchInterval: 20 * time.Millisecond}).Run(
		context.Background(),
		testRequest(work, "Write-Output 'x'"),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	left, err := filepath.Glob(filepath.Join(work, "sopdet-job-*.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("temp scripts not cleaned: %v", left)
	}
}

func TestRunnerMissingInterpreterFails(t *testing.T) {
	_, err := (&Runner{PowerShellPath: filepath.Join(t.TempDir(), "absent-binary")}).Run(
		context.Background(),
		testRequest(t.TempDir(), "x"),
		nil,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "powershell not found") {
		t.Fatalf("expected interpreter error, got: %v", err)
	}
}

// TestRunnerReturnsWhileDescendantHoldsPipes pins the bifrost#951 wedge:
// the script finished and the direct child exited, but a backgrounded
// descendant that escaped the tree kill still holds the stdout/stderr pipe
// write ends. Run must return within the exit grace so the serve loop can
// post the terminal report — never block on pipe EOF forever while
// heartbeats keep the job pinned server-side.
func TestRunnerReturnsWhileDescendantHoldsPipes(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	pidFile := filepath.Join(t.TempDir(), "orphan.pid")
	// set -m (bash): background jobs get their own process group, so the
	// post-exit group kill cannot reach the orphan — mirroring taskkill /T
	// on Windows, which cannot enumerate the children of an already-exited
	// parent.
	path := filepath.Join(t.TempDir(), "fake-powershell")
	body := fmt.Sprintf(
		"#!/usr/bin/env bash\nset -m\nsleep 60 &\necho $! > %q\necho done\nexit 0\n",
		pidFile,
	)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		var pid int
		if _, err := fmt.Sscanf(string(raw), "%d", &pid); err == nil && pid > 0 {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	})

	var mu sync.Mutex
	var entries []LogEntry
	type runResult struct {
		out RunOutcome
		err error
	}
	finished := make(chan runResult, 1)
	go func() {
		out, err := (&Runner{
			PowerShellPath: path,
			BatchInterval:  20 * time.Millisecond,
			ExitGrace:      500 * time.Millisecond,
		}).Run(
			context.Background(),
			testRequest(t.TempDir(), "x"),
			nil,
			func(batch []LogEntry) {
				mu.Lock()
				entries = append(entries, batch...)
				mu.Unlock()
			},
		)
		finished <- runResult{out, err}
	}()

	// The orphan holds the pipe for 60s; before the fix Run blocked on
	// wg.Wait() for the whole span (no terminal report could ever be sent).
	var res runResult
	select {
	case res = <-finished:
	case <-time.After(10 * time.Second):
		t.Fatalf("Run still blocked 10s after the child exited — " +
			"the serve loop would never post the terminal report (bifrost#951)")
	}
	if res.err != nil {
		t.Fatalf("Run: %v", res.err)
	}
	if res.out.ExitCode != 0 {
		t.Errorf("exit = %d, want 0 (the child succeeded)", res.out.ExitCode)
	}
	mu.Lock()
	defer mu.Unlock()
	var sawDone bool
	for _, e := range entries {
		if strings.Contains(e.Text, "done") {
			sawDone = true
		}
	}
	if !sawDone {
		t.Errorf("pre-exit output lost when the drain was bounded: %+v", entries)
	}
}
