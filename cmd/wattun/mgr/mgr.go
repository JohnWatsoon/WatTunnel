package mgr

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// screenRegistry is the P2/P3/P4 hook table: every bash function that became a
// screen registers under its bash name (dash_table, tunnel_page, wizard_kharej,
// heal, ...). Run and MainMenu dispatch through it, so interactive screens and
// direct commands share one route. A missing entry falls back to dispatch's
// generic "unavailable" error — a programming slip, never a menu path (every
// dispatched name is registered at init).
var screenRegistry = map[string]func(args ...string) int{}

// Register installs a screen under its bash function name (P2/P3/P4 call this
// from init()).
func Register(name string, fn func(args ...string) int) { screenRegistry[name] = fn }

// dispatch runs a registry entry; rc false when nobody registered it.
func dispatch(name string, args ...string) int {
	if fn, ok := screenRegistry[name]; ok {
		return fn(args...)
	}
	Err(fmt.Sprintf("'%s' is not available in this build.", name))
	return 1
}

func registered(name string) bool { _, ok := screenRegistry[name]; return ok }

// usage mirrors usage() verbatim (with $SELF/$VER substituted).
func usage() {
	u := strings.ReplaceAll(usageText, "$SELF", P.Self)
	fmt.Fprintf(Stdout, "WatTun manager %s\n\n%s", Ver, u)
}

// Run mirrors main(): env setup, non-interactive detection, root check, binary
// check, then the command dispatch (or the root menu). Returns the exit code.
func Run(args []string) int {
	if err := InitPaths(); err != nil {
		fmt.Fprintf(Stderr, "%s\n", err)
		return 1
	}
	wireSystem()
	if runtime.GOOS != "linux" {
		_ = os.Getenv("LC_ALL") // the bash forces C.UTF-8; Go handles UTF-8 natively
	}
	// NONINTERACTIVE detection (bash L129-137): the flag, the env, or any
	// --flag on the wizard commands when stdin is not a tty.
	NonInteractive = os.Getenv("NONINTERACTIVE") == "1"
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "kharej", "iran", "cdn-tune", "auto-test", "delete", "uninstall", "matrix", "auto-retest", "bond-retest", "auto-prune":
		for _, a := range args {
			if a == "--yes" {
				NonInteractive = true
			} else if strings.HasPrefix(a, "--") && !stdinIsTTY() {
				NonInteractive = true
			}
		}
	}
	if cmd == "auto-retest" && len(args) > 1 && args[1] == "--yes" {
		NonInteractive = true
	}
	// unattended kharej/iran flags (bash 10201: ni_parse "${@:2}" || exit 1)
	if cmd == "kharej" || cmd == "iran" {
		if err := niParse(args[1:]); err != nil {
			return 1
		}
	}

	// colour / animation / tty gates (bash L146-161, L173-176)
	InitTerm(os.Stdout)
	ncol := colorTierFromEnv()
	useColor := os.Getenv("WAT_FORCE_COLOR") == "1" ||
		(IsTTY && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && os.Getenv("TERM") != "")
	if NonInteractive {
		useColor = false
	}
	InitColor(useColor, ncol)
	UseAnim = IsTTY && os.Getenv("WAT_NO_ANIM") != "1" && ConfGet("anim", "1") == "1"

	// read the binary version the way main() does
	if fileExists(P.Bin) {
		Ver = BinVersion()
	}

	switch cmd {
	case "help", "-h", "--help":
		usage()
		return 0
	}
	if NonInteractive {
		switch cmd {
		case "", "new", "monitor", "ports", "logs":
			Err(fmt.Sprintf("'%s' needs a terminal; unattended use: kharej, iran, cdn-tune, auto-test, delete, uninstall, status, test, token, matrix (see: help)", cmd))
			return 1
		case "delete", "uninstall":
			if !hasFlag(args, "--yes") {
				Err(cmd + " without a terminal needs --yes")
				return 1
			}
		}
	}
	if cmd != "mute" && cmd != "unmute" && os.Geteuid() != 0 {
		Err("Run as root.")
		return 1
	}
	if !fileExists(P.Bin) {
		if P.Sandbox {
			if cmd != "update" {
				Err(fmt.Sprintf("Sandbox %s: no wattun binary at %s yet. Install it with: %s update", P.Prefix, P.Bin, P.Self))
				return 1
			}
		} else {
			Err("wattun is not installed. Run install.sh first.")
			return 1
		}
	}
	switch cmd {
	case "heal", "auto-watch", "auto-retest":
	default:
		if P.Sandbox {
			Hint(fmt.Sprintf("Sandbox %s: configs %s, binary %s, units %s@NAME, runtime %s (production wattun is not touched).",
				P.Prefix, P.Conf, P.Bin, P.Prefix, P.Run))
		}
	}
	if err := os.MkdirAll(P.Conf, 0o700); err != nil {
		Err(err.Error())
		return 1
	}
	if err := os.MkdirAll(P.Run, 0o755); err != nil {
		Err(err.Error())
		return 1
	}
	switch cmd {
	case "uninstall", "update", "mute", "unmute":
	default:
		if registered("ensure_heal_timer") {
			dispatch("ensure_heal_timer")
		}
	}

	// raw mode for the interactive paths; restored on return
	if IsTTY {
		if restore, err := rawMode(); err == nil {
			defer restore()
		}
	}

	return runCommand(cmd, args)
}

// runCommand mirrors the dispatch case block of main(). Commands whose screens
// P2/P3/P4 own route through screenRegistry under the bash function's name;
// the small ones P1 owns run inline.
func runCommand(cmd string, args []string) int {
	name := ""
	if len(args) > 1 {
		name = args[1]
	}
	switch cmd {
	case "":
		return MainMenu()
	case "new":
		return dispatch("new_tunnel", name)
	case "kharej":
		return runFlow("wizard_kharej")
	case "iran":
		return runFlow("wizard_iran")
	case "delete":
		if !NeedTunnel(pos(args, 0)) {
			return 1
		}
		return runFlow("delete_tunnel", pos(args, 0))
	case "uninstall":
		return runFlow("uninstall_all")
	case "status", "list", "status-all":
		return dispatch("status_all")
	case "start-all":
		return dispatch("start_all")
	case "stop-all":
		return dispatch("stop_all")
	case "restart-all":
		return dispatch("restart_all")
	case "backup":
		return dispatch("backup_cmd", args[1:]...)
	case "restore":
		return dispatch("restore_cmd", args[1:]...)
	case "boost":
		return dispatch("boost_cmd", args[1:]...)
	case "auto-optimize":
		return dispatch("auto_optimize_all")
	case "monitor":
		return dispatch("live_monitor")
	case "ports":
		if !NeedTunnel(name) {
			return 1
		}
		return runFlow("edit_ports", name)
	case "test":
		if !NeedTunnel(name) {
			return 1
		}
		return dispatch("test_tunnel", name)
	case "speedtest":
		if !NeedTunnel(name) {
			return 1
		}
		mb := "10"
		if len(args) > 2 && args[2] != "" {
			mb = args[2]
		}
		return dispatch("speed_test", name, mb)
	case "mute":
		return dispatch("mute_cmd", name, pos(args, 1))
	case "unmute":
		return dispatch("unmute_cmd", name, pos(args, 1))
	case "logs":
		if !NeedTunnel(name) {
			return 1
		}
		return journalFollowRC(Unit(name))
	case "token":
		if !NeedTunnel(name) {
			return 1
		}
		return dispatch("show_token", name)
	case "preset":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("preset_cmd", posNI(args, 0), posNI(args, 1))
	case "test-anticensor", "test-bypass":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("anticensor_test", posNI(args, 0))
	case "profile":
		return dispatch("profile_cmd", args[1:]...)
	case "blackout":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("blackout_cmd", posNI(args, 0), posNI(args, 1))
	case "arm-blackout":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("arm_blackout_cmd", posNI(args, 0))
	case "audit-blackout":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("audit_blackout_cmd", posNI(args, 0))
	case "matrix", "anti-censor-matrix":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("ac_matrix_cmd", posNI(args, 0))
	case "reset-traffic":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("reset_traffic", posNI(args, 0))
	case "heal":
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("heal")
	case "auto-test":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("auto_test_cmd", posNI(args, 0))
	case "auto-ip":
		if !NeedTunnel(name) {
			return 1
		}
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("auto_ip", name, pos(args, 2))
	case "auto-widen":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("auto_reopen", posNI(args, 0))
	case "auto-narrow", "auto-prune":
		Hint("Auto carrier lifecycle is automatic now; test carriers stay open in the background.")
		return 0
	case "auto-watch":
		if !NeedTunnel(name) {
			return 1
		}
		return dispatch("auto_watch", name)
	case "auto-retest":
		if !NeedTunnel(name) {
			return 1
		}
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("auto_retest", name)
	case "bond-retest":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		if dispatch("mgr_lock") != 0 { // lock held (bash: mgr_lock || return 0)
			return 0
		}
		return dispatch("bond_retest_job", posNI(args, 0))
	case "cdn-tune":
		if !NeedTunnel(posNI(args, 0)) {
			return 1
		}
		return dispatch("cdn_tune_cmd", posNI(args, 0), posNI(args, 1))
	case "iran-firewall", "anti-access":
		return dispatch("iran_firewall_cmd", args[1:]...)
	case "update":
		return dispatch("update", args[1:]...)
	case "rollback":
		return dispatch("rollback")
	case "bundle":
		return dispatch("bundle_cmd", args[1:]...)
	}
	usage()
	return 1
}

// runFlow mirrors run_flow(): a Ctrl-C-cancellable flow; rc 130 prints
// "Cancelled.". P1 only routes — the trap semantics live with the screens.
func runFlow(name string, args ...string) int {
	if NonInteractive {
		return dispatch(name, args...)
	}
	rc := dispatch(name, args...)
	if rc == 130 {
		fmt.Fprintln(Stdout)
		Warn("Cancelled.")
		if IsTTY {
			sleepMS(800)
		}
	}
	return rc
}

func journalFollowRC(unit string) int {
	if err := JournalFollow(unit); err != nil {
		return 1
	}
	return 0
}

// pos returns args[i] after the command word, skipping --flags (positional
// words, NI_POS); "" when absent.
func pos(args []string, i int) string { return posFrom(args, 1, i) }

// posNI returns the i-th positional word of the whole arg list (NI_POS form the
// ni_parse side fills; here the plain positional filter).
func posNI(args []string, i int) string { return posFrom(args, 1, i) }

func posFrom(args []string, start, i int) string {
	n := 0
	for _, a := range args[start:] {
		if strings.HasPrefix(a, "--") {
			continue
		}
		if n == i {
			return a
		}
		n++
	}
	return ""
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func sleepMS(ms int) { sleep(time.Duration(ms) * time.Millisecond) }

// arg returns args[i] or "": registry handlers get their arguments without the
// command word, so they index directly (pos skips args[0]).
func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}
