package collect

import (
	"context"
	"os/exec"
)

// assessExec runs a helper command for assessment collectors. All sources
// here are read-only OS queries; nothing is installed or modified.
func assessExec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// assessCombined is assessExec with stderr merged into the output, for
// collectors that fail loud and need the reason in the entity error.
func assessCombined(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
