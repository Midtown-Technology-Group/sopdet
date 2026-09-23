//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"syscall"
)

func defaultPowerShellPath() string {
	return "powershell.exe"
}

func configureProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// killTree force-terminates the spawned process and its children.
func killTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	// taskkill /T removes the whole tree; fall back to a direct kill.
	killer := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid))
	if killer.Run() != nil {
		_ = cmd.Process.Kill()
	}
}
