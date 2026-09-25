//go:build windows

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Midtown-Technology-Group/sopdet/internal/agent"
	"golang.org/x/sys/windows/svc"
)

// serveHandler adapts resident serve mode to the Windows service control
// dispatcher. The first 2026-09-25 canary run proved the gap this closes:
// without a dispatcher registration, the SCM start times out at ~30s and
// reaps the process — the agent got one heartbeat and then reported
// STOPPED with exit 0/0, silently.
type serveHandler struct {
	serveCfgPath string
	flags        agent.ServeConfig
	exitCode     uint32
}

// Execute runs the serve loop for the lifetime of the service request.
// Stop/Shutdown cancel the root context so the claim loop drains its
// current claim path and returns; a nonzero serve exit is surfaced to the
// SCM as a service-specific failure so `sc failure` recovery applies.
func (h *serveHandler) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() { done <- serveWithContext(ctx, h.serveCfgPath, h.flags) }()

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case code := <-done:
			h.exitCode = uint32(code)
			if code == 0 {
				// Root context cancelled without an explicit SCM stop
				// (console-equivalent exit): report a clean stop.
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			// Exited on its own with a failure: let the SCM record the
			// service-specific code and run the failure actions.
			return true, h.exitCode
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				code := <-done
				h.exitCode = uint32(code)
				status <- svc.Status{State: svc.Stopped}
				return false, h.exitCode
			case svc.Interrogate:
				status <- req.CurrentStatus
			}
		}
	}
}

// maybeRunAsService enters the SCM dispatcher when this process was started
// as a Windows service. It returns handled=false for interactive/console
// runs so the plain signal-driven path keeps working unchanged.
func maybeRunAsService(serveCfgPath string, flags agent.ServeConfig) (bool, int) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, 0
	}
	h := &serveHandler{serveCfgPath: serveCfgPath, flags: flags}
	if err := svc.Run("", h); err != nil {
		fmt.Fprintf(os.Stderr, "service dispatcher error: %v\n", err)
		return true, 1
	}
	return true, int(h.exitCode)
}
