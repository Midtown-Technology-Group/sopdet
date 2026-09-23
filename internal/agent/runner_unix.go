//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

func defaultPowerShellPath() string {
	return "powershell"
}

func configureProc(cmd *exec.Cmd) {
	// Own process group so timeout kills reach children.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree force-terminates the spawned process group. Non-Windows hosts
// are development/test environments; production agents run on Windows.
func killTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
