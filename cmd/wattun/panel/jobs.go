package panel

// Jobs are the panel's long actions (create, delete, update, backup, restore, carrier test, speed test). Each one
// lives on disk under DATA/jobs: ID.json (what and who), ID.log (its output), ID.rc (exit code, written when it
// ends). A self-update restarts the panel mid-job; the job keeps running (systemd-run puts it in its own unit,
// outside the panel's cgroup) and the page reads its end state from the files after the restart.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const jobsKeep = 60

type jobMeta struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	User    string `json:"user"`
	Started int64  `json:"started"`
	Unit    string `json:"unit,omitempty"` // the transient systemd unit, when it runs in one
}

// JobView is what the page polls.
type JobView struct {
	jobMeta
	State  string            `json:"state"` // running | done | failed | lost
	RC     int               `json:"rc"`
	Log    []string          `json:"log"`
	Result map[string]string `json:"result,omitempty"` // KEY=VALUE lines of the manager's unattended output
}

type jobs struct {
	dir     string
	mu      sync.Mutex
	running map[string]bool // in-process jobs of this panel run
	useUnit bool            // systemd-run available (Linux, root)
}

func newJobs(dir string) *jobs {
	j := &jobs{dir: dir, running: map[string]bool{}}
	if dir != "" {
		os.MkdirAll(dir, 0o700)
		j.prune()
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if _, err := exec.LookPath("systemd-run"); err == nil {
			j.useUnit = true
		}
	}
	return j
}

func (j *jobs) path(id, ext string) string { return filepath.Join(j.dir, id+"."+ext) }

func (j *jobs) newMeta(kind, title, user string) jobMeta {
	return jobMeta{ID: time.Now().UTC().Format("20060102-150405") + "-" + strings.ToLower(RandToken(4)[:5]),
		Kind: kind, Title: title, User: user, Started: time.Now().Unix()}
}

func (j *jobs) writeMeta(m jobMeta) error {
	b, _ := json.Marshal(m)
	return os.WriteFile(j.path(m.ID, "json"), b, 0o600)
}

// run starts ARGV as a job. env adds KEY=VALUE pairs (plus every WAT_* of the panel, so a sandbox prefix carries).
func (j *jobs) run(kind, title, user string, argv []string, env ...string) (string, error) {
	m := j.newMeta(kind, title, user)
	env = append(env, "NONINTERACTIVE=1", "NO_COLOR=1", "WAT_NO_ANIM=1")
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "WAT_") {
			env = append(env, e)
		}
	}
	logf, rcf := j.path(m.ID, "log"), j.path(m.ID, "rc")
	if j.useUnit {
		m.Unit = "panel-job-" + m.ID
		if err := j.writeMeta(m); err != nil {
			return "", err
		}
		a := []string{"--unit=" + m.Unit, "--collect", "--quiet", "--property=TimeoutStopSec=30"}
		for _, e := range env {
			a = append(a, "--setenv="+e)
		}
		// argv goes through "$@": nothing user-typed is ever parsed by the shell
		a = append(a, "--", "/bin/sh", "-c", `l=$1; r=$2; shift 2; "$@" >"$l" 2>&1 </dev/null; echo $? >"$r"`, "sh", logf, rcf)
		a = append(a, argv...)
		if out, err := exec.Command("systemd-run", a...).CombinedOutput(); err != nil {
			os.Remove(j.path(m.ID, "json"))
			return "", fmt.Errorf("could not start the job: %v %s", err, strings.TrimSpace(string(out)))
		}
		return m.ID, nil
	}
	if err := j.writeMeta(m); err != nil {
		return "", err
	}
	f, err := os.OpenFile(logf, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		f.Close()
		os.WriteFile(rcf, []byte("127\n"), 0o600)
		return m.ID, nil
	}
	j.setRunning(m.ID, true)
	go func() {
		err := cmd.Wait()
		f.Close()
		rc := 0
		if err != nil {
			rc = 1
			if ee, ok := err.(*exec.ExitError); ok {
				rc = ee.ExitCode()
			}
		}
		os.WriteFile(rcf, []byte(strconv.Itoa(rc)+"\n"), 0o600)
		j.setRunning(m.ID, false)
	}()
	return m.ID, nil
}

// do runs FN inside the panel as a job; FN writes its progress lines through say. An error fails the job.
func (j *jobs) do(kind, title, user string, fn func(say func(format string, a ...any)) error) (string, error) {
	m := j.newMeta(kind, title, user)
	if err := j.writeMeta(m); err != nil {
		return "", err
	}
	f, err := os.OpenFile(j.path(m.ID, "log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	j.setRunning(m.ID, true)
	go func() {
		var mu sync.Mutex
		say := func(format string, a ...any) {
			mu.Lock()
			fmt.Fprintf(f, format+"\n", a...)
			mu.Unlock()
		}
		rc := 0
		func() {
			defer func() {
				if p := recover(); p != nil {
					say("error: %v", p)
					rc = 1
				}
			}()
			if err := fn(say); err != nil {
				say("error: %v", err)
				rc = 1
			}
		}()
		f.Close()
		os.WriteFile(j.path(m.ID, "rc"), []byte(strconv.Itoa(rc)+"\n"), 0o600)
		j.setRunning(m.ID, false)
	}()
	return m.ID, nil
}

func (j *jobs) setRunning(id string, on bool) {
	j.mu.Lock()
	if on {
		j.running[id] = true
	} else {
		delete(j.running, id)
	}
	j.mu.Unlock()
}

func validJobID(id string) bool {
	if len(id) < 10 || len(id) > 40 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// get reads job ID from disk.
func (j *jobs) get(id string) (JobView, bool) {
	var v JobView
	if !validJobID(id) {
		return v, false
	}
	b, err := os.ReadFile(j.path(id, "json"))
	if err != nil || json.Unmarshal(b, &v.jobMeta) != nil {
		return v, false
	}
	v.Log, v.Result = tailLog(j.path(id, "log"), 400)
	if rc, err := os.ReadFile(j.path(id, "rc")); err == nil {
		v.RC, _ = strconv.Atoi(strings.TrimSpace(string(rc)))
		v.State = "done"
		if v.RC != 0 {
			v.State = "failed"
		}
		return v, true
	}
	v.State = "running"
	j.mu.Lock()
	mine := j.running[id]
	j.mu.Unlock()
	if !mine && time.Since(time.Unix(v.Started, 0)) > 10*time.Second {
		alive := false
		if v.Unit != "" {
			alive = exec.Command("systemctl", "is-active", "--quiet", v.Unit).Run() == nil
		}
		if !alive {
			v.State, v.RC = "lost", -1 // the panel restarted under an in-process job, or the unit died without a code
		}
	}
	return v, true
}

func tailLog(file string, n int) ([]string, map[string]string) {
	f, err := os.Open(file)
	if err != nil {
		return []string{}, nil
	}
	defer f.Close()
	var lines []string
	res := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(f, 8<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if k, v, ok := strings.Cut(l, "="); ok && k != "" && strings.ToUpper(k) == k && !strings.ContainsAny(k, " \t") {
			res[k] = v
		}
		lines = append(lines, l)
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
	}
	if lines == nil {
		lines = []string{}
	}
	if len(res) == 0 {
		res = nil
	}
	return lines, res
}

// list returns the newest jobs first (no logs).
func (j *jobs) list() []JobView {
	ids := j.ids()
	out := []JobView{}
	for i := len(ids) - 1; i >= 0 && len(out) < 30; i-- {
		if v, ok := j.get(ids[i]); ok {
			v.Log, v.Result = nil, nil
			out = append(out, v)
		}
	}
	return out
}

func (j *jobs) ids() []string {
	m, _ := filepath.Glob(filepath.Join(j.dir, "*.json"))
	ids := make([]string, 0, len(m))
	for _, f := range m {
		ids = append(ids, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	sort.Strings(ids) // ids start with the UTC time: oldest first
	return ids
}

// running reports whether a job of KIND is still running (one update or restore at a time).
func (j *jobs) busy(kind string) bool {
	for _, v := range j.list() {
		if v.Kind == kind && v.State == "running" {
			return true
		}
	}
	return false
}

func (j *jobs) prune() {
	ids := j.ids()
	for i := 0; i < len(ids)-jobsKeep; i++ {
		for _, ext := range []string{"json", "log", "rc"} {
			os.Remove(j.path(ids[i], ext))
		}
	}
}
