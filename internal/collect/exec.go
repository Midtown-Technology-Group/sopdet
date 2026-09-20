package collect

import "os/exec"

// runCommand runs a command and returns stdout (stderr discarded).
func runCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}
