package mgr

// The web panel's console side (plan docs/handoff/PLAN-panel.md D1/D4/D6/D7): `wattun panel on|off|url|reset|
// 2fa|2fa-reset|status` and the Settings → Web panel screen. The panel itself is `wattun -panel FILE`
// (cmd/wattun/panel); this file only writes its config and unit, opens its port and prints how to reach it.

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/JohnWatsoon/WatTunnel/cmd/wattun/panel"
)

func panelConf() string    { return filepath.Join(P.Conf, "panel.conf") }
func panelUnit() string    { return P.Prefix + "-panel" }
func panelDataDir() string { return "/var/lib/" + P.Prefix + "/panel" }
func panelOn() bool        { return IsActive(panelUnit()) }

// panelCmd dispatches `wattun panel SUB`.
func panelCmd(args []string) int {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "on":
		return b2i(panelEnable())
	case "off":
		return b2i(panelDisable(len(args) > 1 && args[1] == "--forget"))
	case "url", "status", "":
		return b2i(panelShow(true))
	case "reset":
		return b2i(panelReset())
	case "2fa":
		return b2i(panel2FAEnroll())
	case "2fa-reset":
		return b2i(panel2FAReset())
	default:
		fmt.Fprintln(Stderr, "usage: wattun panel on | off [--forget] | url | status | reset | 2fa | 2fa-reset")
		return 2
	}
}

func randInt(lo, hi int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	return lo + int(n.Int64())
}

func randLetters(n int) string {
	const a = "abcdefghjkmnpqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[randInt(0, len(a))]
	}
	return string(b)
}

// panelPickPort: random 20000-60000, free, and not a known x-ui/3x-ui default (plan D7).
func panelPickPort() int {
	avoid := map[int]bool{54321: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true, 20000: true}
	for i := 0; i < 200; i++ {
		p := randInt(20000, 60001)
		if !avoid[p] && !portBusy(p, "tcp", false) {
			return p
		}
	}
	return randInt(20000, 60001)
}

// panelEnable writes the config on first use (random port, secret path, username and password, printed once),
// makes the certificate, writes and starts the unit, opens the port. Running it again keeps the credentials.
func panelEnable() bool {
	cfg, err := panel.LoadConfig(panelConf())
	pass := ""
	if err != nil {
		if _, statErr := os.Stat(panelConf()); statErr == nil {
			Err("Cannot read " + panelConf() + ": " + err.Error())
			return false
		}
		host, _ := os.Hostname()
		pass = panel.RandToken(15)
		h, herr := panel.HashPassword(pass)
		if herr != nil {
			Err("Could not hash the password: " + herr.Error())
			return false
		}
		cfg = &panel.Config{Port: panelPickPort(), Path: panel.RandToken(16), Title: orStr(host, "server"),
			User: randLetters(8), PassHash: h}
		_ = os.MkdirAll(P.Conf, 0o755)
		if err := cfg.SaveAs(panelConf()); err != nil {
			Err("Could not write " + panelConf() + ": " + err.Error())
			return false
		}
		if cfg, err = panel.LoadConfig(panelConf()); err != nil {
			Err(err.Error())
			return false
		}
	}
	if err := panel.EnsureCert(cfg.CertFile, cfg.KeyFile, panelIPs()); err != nil {
		Err("Could not make the certificate: " + err.Error())
		return false
	}
	ud := unitDir()
	_ = os.MkdirAll(ud, 0o755)
	svc := "[Unit]\nDescription=WatTunnel web panel\nAfter=network-online.target\nWants=network-online.target\n" +
		"[Service]\n" + unitEnvLines() + "Environment=\"WAT_PANEL_DATA=" + panelDataDir() + "\"\n" +
		"ExecStart=" + P.Bin + " -panel " + panelConf() + "\nRestart=always\nRestartSec=2\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if err := atomicWrite(filepath.Join(ud, panelUnit()+".service"), []byte(svc), 0o644); err != nil {
		Err("Could not write the panel unit: " + err.Error())
		return false
	}
	if Systemctl("daemon-reload") != nil || Systemctl("enable", "--now", panelUnit()+".service") != nil {
		Err("The panel did not start. Look at: journalctl -u " + panelUnit())
		return false
	}
	fwOpen(strconv.Itoa(cfg.Port) + "/tcp")
	Ok("Web panel is on.")
	panelPrint(cfg, pass)
	return true
}

func panelDisable(forget bool) bool {
	cfg, _ := panel.LoadConfig(panelConf())
	_ = Systemctl("disable", "--now", panelUnit()+".service")
	_ = os.Remove(filepath.Join(unitDir(), panelUnit()+".service"))
	_ = Systemctl("daemon-reload")
	if cfg != nil {
		fwClose(strconv.Itoa(cfg.Port) + "/tcp")
	}
	if forget {
		if cfg != nil {
			_ = os.Remove(cfg.CertFile)
			_ = os.Remove(cfg.KeyFile)
		}
		_ = os.Remove(panelConf())
		_ = os.RemoveAll(panelDataDir())
		Ok("Web panel is off; its address, password and records are deleted.")
	} else {
		Ok("Web panel is off. `" + P.Self + " panel on` brings it back at the same address.")
	}
	return true
}

// panelIPs: this server's addresses for the certificate (public first).
func panelIPs() []net.IP {
	var out []net.IP
	if ip := net.ParseIP(publicIP()); ip != nil {
		out = append(out, ip)
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() && !n.IP.Equal(firstIP(out)) {
			out = append(out, n.IP)
		}
	}
	return out
}

func firstIP(l []net.IP) net.IP {
	if len(l) == 0 {
		return nil
	}
	return l[0]
}

func panelURL(cfg *panel.Config) string {
	host := orStr(publicIP(), "SERVER-IP")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("https://%s:%d/%s/", host, cfg.Port, cfg.Path)
}

// panelPrint shows how to reach the panel. pass is printed only when it was just made (it is stored hashed).
func panelPrint(cfg *panel.Config, pass string) {
	u := panelURL(cfg)
	fmt.Fprintln(Stdout)
	fmt.Fprintf(Stdout, "  %sAddress%s   %s%s%s\n", GRY, RST, BOLD, u, RST)
	fmt.Fprintf(Stdout, "  %sUsername%s  %s\n", GRY, RST, cfg.User)
	if pass != "" {
		fmt.Fprintf(Stdout, "  %sPassword%s  %s%s%s   %s(shown once; `%s panel reset` makes a new one)%s\n", GRY, RST, BOLD+YEL, pass, RST, GRY, P.Self, RST)
	}
	twofa := "off · turn it on in the panel (Settings) or with `" + P.Self + " panel 2fa`"
	if cfg.TOTP != "" {
		twofa = "on"
	}
	fmt.Fprintf(Stdout, "  %s2FA%s       %s\n", GRY, RST, twofa)
	if fp := panel.CertFingerprint(cfg.CertFile); fp != "" {
		fmt.Fprintf(Stdout, "  %sCertificate SHA-256%s\n  %s\n", GRY, RST, fp)
		Hint("The browser warns once (the certificate is made on this server). Check its SHA-256 matches the one above.")
	}
	if q, err := panel.EncodeQR(u); err == nil && IsTTY {
		fmt.Fprintln(Stdout)
		fmt.Fprint(Stdout, q.Terminal())
	}
	fmt.Fprintln(Stdout)
}

func panelShow(withQR bool) bool {
	cfg, err := panel.LoadConfig(panelConf())
	if err != nil {
		Hint("The web panel is off. Turn it on with: " + P.Self + " panel on")
		return false
	}
	if panelOn() {
		Ok("Web panel is running.")
	} else {
		Warn("Web panel is set up but not running. Start it with: " + P.Self + " panel on")
	}
	if out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output(); err == nil &&
		strings.TrimSpace(string(out)) != "yes" {
		Warn("This server's clock is not synced; 2FA codes may be refused.")
	}
	if !withQR {
		return true
	}
	panelPrint(cfg, "")
	return true
}

func panelRestartIfOn() {
	if panelOn() {
		_ = Systemctl("restart", panelUnit()+".service")
	}
}

func panelReset() bool {
	cfg, err := panel.LoadConfig(panelConf())
	if err != nil {
		Err("The web panel is not set up (" + P.Self + " panel on).")
		return false
	}
	pass := panel.RandToken(15)
	h, err := panel.HashPassword(pass)
	if err == nil {
		cfg.PassHash = h
		err = cfg.Save()
	}
	if err != nil {
		Err(err.Error())
		return false
	}
	panelRestartIfOn() // also signs every browser out
	Ok("New password set; every browser was signed out.")
	panelPrint(cfg, pass)
	return true
}

func panel2FAReset() bool {
	cfg, err := panel.LoadConfig(panelConf())
	if err != nil {
		Err("The web panel is not set up (" + P.Self + " panel on).")
		return false
	}
	cfg.TOTP, cfg.TOTPLast, cfg.Recovery = "", 0, nil
	if err := cfg.Save(); err != nil {
		Err(err.Error())
		return false
	}
	panelRestartIfOn()
	Ok("2FA is off. Turn it on again in the panel or with `" + P.Self + " panel 2fa`.")
	return true
}

// panel2FAEnroll sets up 2FA from the console: QR + key, then one code to confirm.
func panel2FAEnroll() bool {
	cfg, err := panel.LoadConfig(panelConf())
	if err != nil {
		Err("The web panel is not set up (" + P.Self + " panel on).")
		return false
	}
	sec := panel.NewTOTPSecret()
	uri := panel.TOTPURI(cfg.Title, cfg.User, sec)
	fmt.Fprintln(Stdout)
	Hint("Scan this with an authenticator app (Google Authenticator, Aegis, 2FAS, Bitwarden…):")
	if q, err := panel.EncodeQR(uri); err == nil {
		fmt.Fprint(Stdout, q.Terminal())
	}
	fmt.Fprintf(Stdout, "  %sOr type this key%s  %s\n\n", GRY, RST, sec)
	var code string
	if IsTTY {
		code = Ask("6-digit code from the app", "")
	} else {
		fmt.Fprint(Stdout, "  6-digit code: ")
		code, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	step, ok := panel.VerifyTOTP(sec, code, time.Now(), 0)
	if !ok {
		Err("That code does not match. Check the phone's and the server's time, then run this again.")
		return false
	}
	plain, hashed := panel.NewRecoveryCodes()
	cfg.TOTP, cfg.TOTPLast, cfg.Recovery = sec, step, hashed
	if err := cfg.Save(); err != nil {
		Err(err.Error())
		return false
	}
	panelRestartIfOn()
	Ok("2FA is on.")
	Hint("Recovery codes, each works once. Keep them somewhere safe; they are not shown again:")
	for _, c := range plain {
		fmt.Fprintf(Stdout, "    %s\n", c)
	}
	return true
}

// panelMenu is Settings → Web panel.
func panelMenu() {
	sel := 0
	for {
		_, cerr := panel.LoadConfig(panelConf())
		items := []Item{}
		if panelOn() {
			items = append(items,
				Item{Key: "u", Label: "Show address", Desc: "address, username, certificate, QR code"},
				Item{Key: "2", Label: "Two-factor", Desc: "set up 2FA with a QR code"},
				Item{Key: "r", Label: "New password", Desc: "signs every browser out"},
				Item{Key: "x", Label: "Turn 2FA off", Desc: "if the phone is lost"},
				Item{Key: "o", Label: RED + "Turn off" + RST, Desc: "stops it and closes its port; the address is kept"})
		} else {
			d := "manage tunnels and Kharej from a browser"
			if cerr == nil {
				d = "set up before; comes back at the same address"
			}
			items = append(items, Item{Key: "n", Label: "Turn on", Desc: d})
		}
		head := func(w io.Writer) { Title(w, "Web panel", onOff(panelOn())) }
		i, k := Choose(head, items, &sel, []string{"⏎", "run", "esc", "back"}, 0)
		if k == "esc" || k == "q" || k == "eof" || k == "0" {
			return
		}
		if i < 0 {
			continue
		}
		ClearScreen()
		switch items[i].Key {
		case "n":
			panelEnable()
		case "u":
			panelShow(true)
		case "2":
			panel2FAEnroll()
		case "r":
			panelReset()
		case "x":
			panel2FAReset()
		case "o":
			panelDisable(false)
		}
		Pause()
		ClearScreen()
	}
}
