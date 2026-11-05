package main

// F8 (3.3.0): where the quota-usage and lifetime-totals state files live, and how often they are written.
//
// The files have always been named after the config: <config>.quota.json (ports.go loadQuota/save) and
// <config>.totals.json (loadTotals/saveTotals), each written atomically (tmp + rename) so a reader never sees a torn
// file. -state-dir only moves that pair into another directory (e.g. tmpfs /run/wattun, so a busy tunnel's periodic
// rewrite does not wear the disk); the names keep the config's base name, so one directory can hold several tunnels'
// state. The save itself is unchanged and stays atomic. On tmpfs the counters are lost on reboot, and the totals file
// is machine-bound anyway (hostID in ports.go), so the next boot starts from zero, exactly like a config copied to a
// new VPS.
//
// The default (no -state-dir) is the 2.5.0-3.2.x location next to the config, so `wattun-manager reset-traffic` and
// delete-tunnel, which look there, keep working for every existing tunnel.

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// stateDirMode is the permission of a -state-dir created by wattun: operator state, like /etc/wattun.
const stateDirMode = 0o700

// stateSaveMax is the upper bound of -state-save: 30 days (a week was a valid pre-3.3.0 choice). The seconds->Duration
// multiplication overflows above ~292 years, which used to silently turn the periodic save off (audit L9/F21).
const stateSaveMax = 30 * 24 * 60 * 60

// statePaths resolves the quota and totals state files. No -config = no persistence: the names are derived from the
// config path, so a flag-run tunnel has nowhere to put them (2.5.0-3.2.x behavior).
func statePaths(cfgPath, dir string) (quota, totals string) {
	if cfgPath == "" {
		return "", ""
	}
	base := cfgPath
	if dir != "" {
		base = filepath.Join(dir, filepath.Base(cfgPath))
	}
	return base + ".quota.json", base + ".totals.json"
}

// stateSaveInterval validates -state-save (seconds) and returns the period; 0 disables the periodic save (the save on
// shutdown stays).
func stateSaveInterval(secs int) (time.Duration, error) {
	if secs < 0 {
		return 0, fmt.Errorf("-state-save must be 0 (only on shutdown) or more seconds, got %d", secs)
	}
	if secs > stateSaveMax {
		return 0, fmt.Errorf("-state-save must be at most %d seconds (30 days), got %d", stateSaveMax, secs)
	}
	return time.Duration(secs) * time.Second, nil
}

// prepareStateDir creates the -state-dir directory 0700 when it is missing, tightens a pre-existing wider mode to
// 0700, and checks it is a usable directory. Failing at startup is deliberate: a typo or a read-only tmpfs would
// otherwise silently drop quota usage, and a quota-capped port would reopen after every restart.
func prepareStateDir(dir string) error {
	if dir == "" {
		return nil
	}
	switch fi, err := os.Stat(dir); {
	case err == nil:
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		// L11/F24: operator state, like /etc/wattun; an operator-created 0755 must not stay group/world-accessible.
		// Narrower modes are left alone — the write probe below decides whether they work.
		if perm := fi.Mode().Perm(); perm&^stateDirMode != 0 {
			if err := os.Chmod(dir, stateDirMode); err != nil {
				return err
			}
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, stateDirMode); err != nil {
			return err
		}
	default:
		return err
	}
	// Write probe: a read-only or full state directory must fail the start, not silently drop the counters every
	// save interval.
	f, err := os.CreateTemp(dir, ".wattun-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
