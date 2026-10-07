package agent

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// staleScriptPattern matches only the temp script files this agent
	// stages via writeTempScript (Runner.Run removes its own file on
	// every return; the sweep below covers the leftovers from crashes,
	// kills, and power loss).
	staleScriptPattern = "sopdet-job-*.ps1"
	// staleScriptTTL bounds the sweep: only files older than this are
	// removed. Age keeps recent scripts — including a concurrent agent's
	// fresh script — but it is not unconditional protection: a foreign
	// job running longer than the TTL while sharing this dir could lose
	// its script. The sweep runs once at serve startup, before this
	// process stages any script, so this agent's own active file can
	// never exist yet when the sweep runs. 24h is deliberately
	// conservative for a transient file.
	staleScriptTTL = 24 * time.Hour
)

// SweepStaleScripts removes stale per-job script staging files left in dir
// by abnormal shutdowns (Runner.Run already removes its own script on every
// normal return). It is bounded:
//
//   - dir must be an explicitly configured work dir; "" never sweeps (that
//     would mean the shared os.TempDir());
//   - only top-level entries matching staleScriptPattern — no recursion,
//     so nested directories are never entered;
//   - only plain regular files — symlinks, directories, and other modes
//     are skipped, never followed;
//   - only files older than staleScriptTTL — recent scripts are
//     preserved, but age alone is not unconditional protection for a
//     concurrent foreign job running longer than the TTL in the same
//     dir (see the TTL comment above).
//
// It returns the number of files removed. A missing dir is not an error.
func SweepStaleScripts(dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	clean := filepath.Clean(dir)
	entries, err := os.ReadDir(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	cutoff := time.Now().Add(-staleScriptTTL)
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ok, err := filepath.Match(staleScriptPattern, e.Name())
		if err != nil || !ok {
			continue
		}
		// Path boundary: top-level entry of the swept dir only. The
		// join cannot escape: e.Name() comes from ReadDir and names a
		// direct child, and Clean keeps it anchored.
		path := filepath.Join(clean, e.Name())
		if filepath.Dir(path) != clean {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue // symlink, device, socket, ... — never follow
		}
		if !info.ModTime().Before(cutoff) {
			continue // fresh: possibly an active job's script
		}
		if os.Remove(path) == nil {
			removed++
		}
	}
	return removed, nil
}
