//go:build windows

package term

import "golang.org/x/sys/windows"

// enableVirtualTerminal turns on ANSI escape processing for the console so the
// branded colour output renders on Windows 10+ conhost, not just Windows
// Terminal. It reports whether colour output is safe to use.
func enableVirtualTerminal() bool {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
