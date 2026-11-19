package mgr

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Unit mirrors "${WAT_PREFIX}@$1": the systemd template instance of a tunnel.
func Unit(name string) string { return P.Prefix + "@" + name }

// Systemctl runs systemctl with exactly the arguments the bash passes and lets
// it write to the terminal; nil error = rc 0.
func Systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = Stdout
	cmd.Stderr = Stderr
	return cmd.Run()
}

// systemctlOK runs systemctl quietly (the bash's -q / >/dev/null forms) and
// reports whether it exited 0.
func systemctlOK(args ...string) bool {
	return exec.Command("systemctl", args...).Run() == nil
}

// IsActive mirrors `systemctl is-active -q unit`.
func IsActive(unit string) bool { return systemctlOK("is-active", "-q", unit) }

// IsEnabled mirrors `systemctl is-enabled -q unit`.
func IsEnabled(unit string) bool { return systemctlOK("is-enabled", "-q", unit) }

// Start/Stop/Restart/Enable/Disable mirror the exact invocations the manager
// uses (quiet where the bash redirects to /dev/null).
func Start(unit string) error   { return Systemctl("start", unit) }
func Stop(unit string) error    { return systemctlErr("stop", unit) }
func Restart(unit string) error { return systemctlErr("restart", unit) }
func Enable(unit string) error  { return systemctlErr("enable", unit) }
func Disable(unit string) error { return systemctlErr("disable", unit) }

func systemctlErr(args ...string) error {
	if err := exec.Command("systemctl", args...).Run(); err != nil {
		return fmt.Errorf("systemctl %v: %w", args, err)
	}
	return nil
}

// EnableNow mirrors `systemctl enable --now unit` (used by tunnel start).
func EnableNow(unit string) error { return Systemctl("enable", "--now", unit) }

// ShowProp mirrors `systemctl show unit -p PROP --value` (uptime_of reads
// ActiveEnterTimestamp); "" when systemd does not answer.
func ShowProp(unit, prop string) string {
	out, err := exec.Command("systemctl", "show", unit, "-p", prop, "--value").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// Journal mirrors the failure path in start_tunnel:
// `journalctl -u unit -n N --no-pager -o cat`.
func Journal(unit string, n int) {
	cmd := exec.Command("journalctl", "-u", unit, "-n", fmt.Sprint(n), "--no-pager", "-o", "cat")
	cmd.Stdout = Stdout
	cmd.Stderr = Stderr
	_ = cmd.Run()
}

// JournalFollow mirrors the `logs` command: `journalctl -u unit -f -o short-iso`.
func JournalFollow(unit string) error {
	cmd := exec.Command("journalctl", "-u", unit, "-f", "-o", "short-iso")
	cmd.Stdout = Stdout
	cmd.Stderr = Stderr
	return cmd.Run()
}

// portUser mirrors port_user(): the process holding a local port ("name
// (PID n)" or "name"), "" when nothing listens.
func portUser(port int, proto string) string {
	flag := "-Hltnp"
	if proto == "udp" {
		flag = "-Hlunp"
	}
	filter := fmt.Sprintf("( sport = :%d )", port)
	out, err := exec.Command("ss", flag, filter).Output()
	if err != nil {
		return ""
	}
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if m := regexp.MustCompile(`users:\(("[^"]*",pid=[0-9]*)`).FindStringSubmatch(l); m != nil {
			line = m[1]
			break
		}
	}
	if line != "" {
		u := strings.Trim(regexp.MustCompile(`^"[^"]*`).FindString(line), `"`)
		pid := regexp.MustCompile(`pid=[0-9]*`).FindString(line)
		if pid != "" && u != "" {
			pidN := strings.TrimPrefix(pid, "pid=")
			return fmt.Sprintf("%s (PID %s)", u, pidN)
		}
		if u != "" {
			return u
		}
	}
	// no pid captured: fall back to the bare process name
	out2, _ := exec.Command("ss", flag, filter).Output()
	for _, l := range strings.Split(string(out2), "\n") {
		if m := regexp.MustCompile(`users:\(("[^"]*"`).FindStringSubmatch(l); m != nil {
			return strings.Trim(m[1], `"`)
		}
	}
	return ""
}

// EnvPortBusy mirrors the port editor's "already in use on this server" check:
// something other than this manager listens on the port.
func EnvPortBusy(port int, proto string) bool { return portUser(port, proto) != "" }

// UptimeOf mirrors uptime_of(): "3d 4h" / "2h 14m" / "5m", "" when unknown.
// systemd timestamps are locale-dependent; parse the common formats and fall
// back to "" (the bash's date -d does the same job and also fails silently).
func UptimeOf(name string) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	raw := ShowProp(Unit(name), "ActiveEnterTimestamp")
	raw = trimEOL(raw)
	if raw == "" {
		return ""
	}
	layouts := []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 MST",
		time.ANSIC,
	}
	for _, lay := range layouts {
		if t, err := time.Parse(lay, raw); err == nil {
			s := int(time.Since(t).Seconds())
			if s < 0 {
				return ""
			}
			switch {
			case s >= 86400:
				return fmt.Sprintf("%dd %dh", s/86400, s%86400/3600)
			case s >= 3600:
				return fmt.Sprintf("%dh %dm", s/3600, s%3600/60)
			default:
				return fmt.Sprintf("%dm", s/60)
			}
		}
	}
	return ""
}

func trimEOL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// BinVersion mirrors `$BIN -version | awk '{print $2}'`.
func BinVersion() string {
	out, err := exec.Command(P.Bin, "-version").Output()
	if err != nil {
		return ""
	}
	fs := fields(string(out))
	if len(fs) >= 2 {
		return fs[1]
	}
	return ""
}

// BinVerOK mirrors bin_ver_ok "X.Y.Z": 1 when the installed binary is new enough
// ("" binary = not installed = not ok).
func BinVerOK(want string) bool {
	return verCompare(BinVersion(), want) >= 0
}

// verCompare compares dotted numeric versions; a = 0, a > b = 1, else -1.
// An empty version sorts below everything.
func verCompare(a, b string) int {
	if a == "" {
		if b == "" {
			return 0
		}
		return -1
	}
	as, bs := verFields(a), verFields(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

func verFields(v string) []int {
	var out []int
	for _, f := range strings.FieldsFunc(strings.ReplaceAll(v, "-", "."), func(r rune) bool { return r == '.' || r == ' ' }) {
		n := 0
		for _, c := range f {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}

func fields(s string) []string {
	var out []string
	cur := ""
	for _, c := range trimEOL(s) + " " {
		if c == ' ' || c == '\t' || c == '\n' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	return out
}
