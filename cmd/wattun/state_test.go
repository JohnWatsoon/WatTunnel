package main

// F8 (3.3.0): state-file path resolution and flag validation. The default must stay the pre-3.3.0 layout next to the
// config file, because wattun-manager's reset-traffic and delete-tunnel look there.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStatePaths(t *testing.T) {
	etc := filepath.Join("/etc", "wattun", "a.yml")
	run := filepath.Join("/run", "wattun")
	rel := filepath.Join("run", "wattun")
	for _, c := range []struct {
		name, cfg, dir string
		quota, totals  string
	}{
		{"no config, no dir", "", "", "", ""}, // no persistence without -config (2.5.0-3.2.x)
		{"no config, dir ignored", "", run, "", ""},
		{"next to the config", etc, "", etc + ".quota.json", etc + ".totals.json"},
		{"relative config", "wat.yml", "", "wat.yml.quota.json", "wat.yml.totals.json"},
		{"state dir", etc, run, filepath.Join(run, "a.yml.quota.json"), filepath.Join(run, "a.yml.totals.json")},
		{"state dir trailing slash", etc, run + string(filepath.Separator), filepath.Join(run, "a.yml.quota.json"), filepath.Join(run, "a.yml.totals.json")},
		{"relative state dir", etc, rel, filepath.Join(rel, "a.yml.quota.json"), filepath.Join(rel, "a.yml.totals.json")},
		{"config base name only", filepath.Join("conf", "t.yml"), run, filepath.Join(run, "t.yml.quota.json"), filepath.Join(run, "t.yml.totals.json")},
	} {
		t.Run(c.name, func(t *testing.T) {
			q, tot := statePaths(c.cfg, c.dir)
			if q != c.quota || tot != c.totals {
				t.Fatalf("statePaths(%q, %q) = %q, %q; want %q, %q", c.cfg, c.dir, q, tot, c.quota, c.totals)
			}
		})
	}
}

func TestStateSaveInterval(t *testing.T) {
	for _, c := range []struct {
		secs    int
		want    time.Duration
		wantErr bool
	}{
		{-1, 0, true}, // negative: only on shutdown is 0, never negative
		{0, 0, false},
		{1, time.Second, false},
		{30, 30 * time.Second, false}, // the default, the 3.2.x every-30-ticks behavior
		{3600, time.Hour, false},
	} {
		got, err := stateSaveInterval(c.secs)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("stateSaveInterval(%d) = %v, %v; want %v, err=%v", c.secs, got, err, c.want, c.wantErr)
		}
	}
}

func TestPrepareStateDir(t *testing.T) {
	t.Run("empty is a no-op", func(t *testing.T) {
		if err := prepareStateDir(""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("creates nested dirs 0700", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "run", "wattun")
		if err := prepareStateDir(dir); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			t.Fatalf("stat %s: %v", dir, err)
		}
		// Windows synthesizes permission bits and ignores MkdirAll's mode; the 0700 check only means something on
		// unix (systemd runs there).
		if runtime.GOOS != "windows" {
			if perm := fi.Mode().Perm(); perm != stateDirMode {
				t.Fatalf("dir mode %o, want %o", perm, stateDirMode)
			}
		}
	})
	t.Run("existing dir is accepted", func(t *testing.T) {
		if err := prepareStateDir(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a file is not a dir", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := prepareStateDir(path); err == nil {
			t.Fatal("accepted a regular file as -state-dir")
		}
	})
	t.Run("unwritable dir fails at startup", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("permission bits are not enforced for this user")
		}
		dir := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := prepareStateDir(dir); err == nil {
			t.Fatal("accepted a read-only -state-dir")
		}
	})
}
