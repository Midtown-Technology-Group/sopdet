//go:build !windows

package term

// enableVirtualTerminal is a no-op off Windows: ANSI escapes are native to
// POSIX terminals.
func enableVirtualTerminal() bool { return true }
