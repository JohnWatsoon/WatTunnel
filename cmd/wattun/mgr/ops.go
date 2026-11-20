package mgr

// Update, offline bundle, roll back, uninstall and auto-heal: ports of the bash
// update, bundle_cmd, rollback, uninstall_all, heal and restart_stale. The
// release check is done in Go (RSA PKCS#1 v1.5 over SHA-256, the same
// signature `openssl dgst -sha256 -verify` checks) with the pinned key.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("update", func(a ...string) int { return b2i(update(a)) })
	Register("rollback", func(a ...string) int { rollback(); return 0 })
	Register("uninstall_all", func(a ...string) int { return b2i(uninstallAll()) })
	Register("bundle_cmd", func(a ...string) int { return b2i(bundleCmd(arg(a, 0), arg(a, 1))) })
	Register("heal", func(a ...string) int { heal(); return 0 })
	Register("wizard_kharej_auto", func(a ...string) int {
		r := wizardKharejAuto(arg(a, 0), autoWizardOpts{Name: os.Getenv("NI_NAME"), CDN: os.Getenv("NI_CDN"),
			Addr: os.Getenv("NI_ADDR"), Ports: os.Getenv("NI_PORTS"), Extended: os.Getenv("NI_EXTENDED") == "1"})
		return errRC(r.Error)
	})
}

// sigPub is the pinned release-signing key (the same one wattun-manager and
// install.sh carry).
const sigPub = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0j+yK26CzKRD+am5rQZJ
v8zChkZ5HuwQ4uBtj2mKfFRG8mrj7XN3iW60QEj7Le/fAYtk4hHvqsxb6Xhxw303
+rFCBxKr+mwc3GOB/zVh/fzNqN2pXzKCT+mSKiaDfwUmCizKFNUUCCnhNVpEx9hl
A4B4n5iBgxW0G/ks4hOujx6teaKUN44+cZNgPshPSQ5KdiqQBi0rFCiSAKBCh1vL
j07u5S/mvU8L8u9M6sUzST0mXcGw9WKQmAiIOCqAwLiyV1RtDodgaCIxLPJ93Qo/
uK4DzYX3Ker8lW6MRKXgX3fAVXoyj/ZaE3oh1ZibVefAy6w7qB74JvQPv4nFvS/Y
VJXpxiHiqE/YMdHbS9eCQnqjHVKmGWvBVPo/IlUiJFbl8nIEFZVij32Cp8A4awO2
IORyD7iC8bA7AZHruzVfiUtrYA5XhBTRJplqws8kM0Ig4sLrws0HPOY4xOBRtSVh
vgY6Qw/EWglth/K24PEC8AiuJYIRRkn/Kq+SBIRu8qVrAgMBAAE=
-----END PUBLIC KEY-----`

func repo() string { return envOr("WAT_REPO", "JohnWatsoon/WatTunnel") }

// sumsVerify checks sig over the SHA256SUMS file with the pinned key (or pubPEM).
func sumsVerify(sums, sig []byte, pubPEM string) bool {
	if pubPEM == "" {
		pubPEM = sigPub
	}
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return false
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return false
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h := sha256.Sum256(sums)
	return rsa.VerifyPKCS1v15(rk, crypto.SHA256, h[:], sig) == nil
}

// sumsHas: SHA256SUMS lists name with exactly this sha.
func sumsHas(sums []byte, name, sha string) bool {
	for _, l := range strings.Split(string(sums), "\n") {
		if strings.TrimRight(l, "\r") == sha+"  "+name {
			return true
		}
	}
	return false
}

func fileSHA(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ---- update proxy (bash update_proxy_env / apply_update_proxy) ----

var (
	uURLPrefix string // mirror prefix put in front of every URL
	uProxy     string // proxy URL for the HTTP client
)

var (
	proxyHTTPRe  = regexp.MustCompile(`^http://([^/]*@)?(\[[0-9a-fA-F:]+\]|[^/:]+):[0-9]{1,5}/?$`)
	proxyHTTPSRe = regexp.MustCompile(`^https://([^/]*@|(127\.|localhost|\[::1\])[^/]*(:[0-9]{1,5})?/?$)`)
	proxyBareRe  = regexp.MustCompile(`^(\[[0-9a-fA-F:]+\]|[^/:]+):[0-9]{1,5}$`)
)

// applyUpdateProxy sorts a Settings value into a mirror prefix or a proxy.
func applyUpdateProxy(v string) {
	uURLPrefix, uProxy = "", ""
	switch {
	case v == "":
	case strings.HasPrefix(v, "socks"):
		uProxy = v
	case strings.HasPrefix(v, "http://"):
		if proxyHTTPRe.MatchString(v) {
			uProxy = strings.TrimSuffix(v, "/")
		} else {
			uURLPrefix = strings.TrimSuffix(v, "/") + "/"
		}
	case strings.HasPrefix(v, "https://"):
		if proxyHTTPSRe.MatchString(v) {
			uProxy = strings.TrimSuffix(v, "/")
		} else {
			uURLPrefix = strings.TrimSuffix(v, "/") + "/"
		}
	case proxyBareRe.MatchString(v):
		uProxy = "http://" + v
	default:
		uURLPrefix = strings.TrimSuffix(v, "/") + "/"
	}
}

func updateProxyEnv() {
	uURLPrefix, uProxy = os.Getenv("WAT_PROXY"), os.Getenv("WAT_CURL_PROXY")
	if uURLPrefix != "" {
		uURLPrefix = strings.TrimSuffix(uURLPrefix, "/") + "/"
	}
	if uURLPrefix == "" && uProxy == "" {
		applyUpdateProxy(ConfGet("update-proxy", ""))
	}
}

func updClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if uProxy != "" {
		p := strings.Replace(uProxy, "socks5h://", "socks5://", 1) // Go's socks5 resolves on the proxy already
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{Transport: tr, Timeout: 90 * time.Second}
}

// download fetches u to dst with 4 retries.
func download(dst, u string) error {
	var last error
	for try := 0; try < 5; try++ {
		if try > 0 {
			time.Sleep(time.Duration(try) * time.Second)
		}
		resp, err := updClient().Get(u)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			last = fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
			continue
		}
		f, err := os.Create(dst)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, err = io.Copy(f, resp.Body)
		resp.Body.Close()
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			return nil
		}
		last = err
	}
	return last
}

// spin shows a spinner line while fn runs (plain line without animation).
func spin(label string, fn func() error) error {
	if !UseAnim {
		Say("  " + label + "...")
		return fn()
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	fr := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	CurHide()
	defer CurShow()
	for i := 0; ; i++ {
		select {
		case err := <-done:
			fmt.Fprint(Stdout, "\r\x1b[K")
			return err
		case <-time.After(100 * time.Millisecond):
			fmt.Fprintf(Stdout, "\r\x1b[K  %s%c%s %s", CYN, fr[i%len(fr)], RST, label)
		}
	}
}

// ---- update ----

func managerPath() string {
	if P.Sandbox && P.Mgr == "/usr/local/bin/wattun-manager" {
		return filepath.Join(filepath.Dir(P.Bin), "wattun-manager")
	}
	return P.Mgr
}

func fileCksum(p string) string { return fileSHA(p) }

// update fetches install.sh from the latest release (or an offline bundle),
// checks it against the signed SHA256SUMS, runs it, then offers to restart
// tunnels still on the old binary.
func update(args []string) bool {
	from := ""
	var pass []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--from":
			if i+1 >= len(args) {
				Err("--from needs a path to a .tar.gz bundle or directory")
				return false
			}
			from = args[i+1]
			i++
		case strings.HasPrefix(a, "--from="):
			from = strings.TrimPrefix(a, "--from=")
		case from == "" && (dirHasInstaller(a) || strings.HasSuffix(a, ".tar.gz") || strings.HasSuffix(a, ".tgz")):
			from = a
		default:
			pass = append(pass, a)
		}
	}
	imgr := managerPath()
	var ienv []string
	udir, err := os.MkdirTemp("", "wattun-update.*")
	if err != nil {
		Err("Cannot create a temporary directory")
		return false
	}
	defer os.RemoveAll(udir)
	if P.Sandbox {
		for _, a := range pass {
			if a == "--uninstall" {
				Err("Sandbox: use the manager's uninstall (Settings), not the installer's --uninstall (it removes the production units).")
				return false
			}
		}
		if err := os.MkdirAll(filepath.Dir(P.Bin), 0o755); err != nil {
			Err("Cannot create " + filepath.Dir(P.Bin))
			return false
		}
		Say(fmt.Sprintf("  Sandbox %s: the update writes only %s, %s and %s (not /usr/local/bin, not wattun@.service).", P.Prefix, P.Bin, imgr, P.Conf))
		ienv = append(ienv, "WAT_BIN="+P.Bin, "WAT_MGR="+imgr, "WAT_CONF="+P.Conf, "WAT_UNIT="+filepath.Join(udir, "unit"), "WAT_REQUIRE_SANDBOX=1")
	}
	updateProxyEnv()
	if uURLPrefix != "" {
		ienv = append(ienv, "WAT_PROXY="+uURLPrefix)
	}
	if uProxy != "" {
		ienv = append(ienv, "WAT_CURL_PROXY="+uProxy)
	}
	before, mbefore := BinVersion(), fileCksum(imgr)
	inst := filepath.Join(udir, "install.sh")
	switch {
	case from != "":
		dir, ok := resolveOfflineBundle(from, filepath.Join(udir, "bundle"))
		if !ok {
			return false
		}
		inst = filepath.Join(dir, "install.sh")
		if os.Getenv("WAT_ALLOW_UNSIGNED_UPDATE") != "1" {
			sums, e1 := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
			sig, e2 := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
			if e1 != nil || e2 != nil {
				Err("Offline bundle '" + from + "' is missing SHA256SUMS or SHA256SUMS.sig.")
				return false
			}
			if !sumsVerify(sums, sig, "") {
				Err("Signature verification failed on the bundle's SHA256SUMS.")
				return false
			}
			if !sumsHas(sums, "install.sh", fileSHA(inst)) {
				Err("install.sh checksum does not match signed SHA256SUMS.")
				return false
			}
			Ok("Offline bundle verified against the pinned release key")
		} else {
			Warn("WAT_ALLOW_UNSIGNED_UPDATE=1: running offline installer without checking SHA256SUMS.sig.")
		}
		ienv = append(ienv, "WAT_OFFLINE_DIR="+dir)
	case os.Getenv("WAT_ALLOW_UNSIGNED_UPDATE") == "1":
		Warn("WAT_ALLOW_UNSIGNED_UPDATE=1: fetching the installer without a signature check (only if you trust the source).")
		u := uURLPrefix + "https://raw.githubusercontent.com/" + repo() + "/main/install.sh"
		if err := spin("Downloading the installer", func() error { return download(inst, u) }); err != nil || !startsWithShebang(inst) {
			Err("Update failed (could not download the installer). If GitHub is blocked: " + P.Self + " update --from <bundle.tar.gz> or set an update proxy in Settings.")
			return false
		}
		Ok("Installer downloaded UNSIGNED")
	default:
		base := uURLPrefix + "https://github.com/" + repo() + "/releases/latest/download"
		sumsP, sigP := filepath.Join(udir, "SHA256SUMS"), filepath.Join(udir, "SHA256SUMS.sig")
		dlErr := spin("Downloading the installer and its signature", func() error {
			for _, f := range [][2]string{{inst, "install.sh"}, {sumsP, "SHA256SUMS"}, {sigP, "SHA256SUMS.sig"}} {
				if err := download(f[0], base+"/"+f[1]); err != nil {
					return err
				}
			}
			return nil
		})
		verified := false
		if dlErr == nil {
			sums, _ := os.ReadFile(sumsP)
			sig, _ := os.ReadFile(sigP)
			verified = sumsVerify(sums, sig, "") && sumsHas(sums, "install.sh", fileSHA(inst))
		}
		if !verified {
			if dlErr != nil && IsTTY && !NonInteractive && os.Getenv("WAT_U_RETRIED") == "" {
				Warn("Could not reach GitHub from this server.")
				Hint("Tip: on Kharej run '" + P.Self + " bundle', copy wattun-offline-<arch>.tar.gz here, or enter an HTTP/SOCKS5 proxy or mirror.")
				if v := Ask("Proxy/mirror URL or path to offline .tar.gz (Enter = cancel)", ""); v != "" {
					os.Setenv("WAT_U_RETRIED", "1")
					defer os.Unsetenv("WAT_U_RETRIED")
					if fileExists(v) {
						return update(append([]string{"--from", v}, pass...))
					}
					if Confirm("Save '"+v+"' in Settings for future updates?", true) {
						_ = ConfSet("update-proxy", v)
					}
					applyUpdateProxy(v)
					os.Setenv("WAT_PROXY", uURLPrefix)
					os.Setenv("WAT_CURL_PROXY", uProxy)
					return update(pass)
				}
			}
			Hint("The latest release must ship install.sh with SHA256SUMS and SHA256SUMS.sig signed by the pinned key.")
			Err("Cannot verify the installer against the signed release; refusing to run it unverified. On filtered Iran hosts, build a signed bundle on Kharej (" + P.Self + " bundle) and run: " + P.Self + " update --from wattun-offline-amd64.tar.gz")
			return false
		}
		Ok("Installer verified against the signed release")
	}
	keep := filepath.Join(udir, "manager.keep")
	_ = copyFile(imgr, keep, 0o755)
	cmd := exec.Command("bash", append([]string{inst}, pass...)...)
	cmd.Env = append(append(os.Environ(), ienv...), "WAT_FROM_MANAGER=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		Err("The installer reported an error. Nothing was changed: still wattun " + orStr(before, "?") + ".")
		return false
	}
	if P.Sandbox && fileExists(keep) {
		if b, _ := os.ReadFile(imgr); !strings.Contains(string(b), "WAT_PREFIX") {
			_ = copyFile(keep, imgr, 0o755)
			Err("The new manager has no sandbox (WAT_PREFIX) support; the previous manager was restored.")
			return false
		}
	}
	after := BinVersion()
	Ver = after
	fmt.Fprintln(Stdout)
	switch {
	case after == "":
		Err(P.Bin + " does not run after the update. Roll back from Tools → Roll back.")
		return false
	case after != before:
		Ok("wattun updated: " + BOLD + orStr(before, "none") + " → " + after + RST)
	default:
		Ok("wattun is already the latest release (" + BOLD + after + RST + ").")
	}
	if fileCksum(imgr) != mbefore {
		Ok("Manager updated.")
	}
	restartStale()
	return true
}

func dirHasInstaller(d string) bool { return fileExists(filepath.Join(d, "install.sh")) }

func startsWithShebang(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 2)
	n, _ := f.Read(b)
	return n == 2 && string(b) == "#!"
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// resolveOfflineBundle returns the directory holding install.sh: the path
// itself, or the archive extracted under dst.
func resolveOfflineBundle(src, dst string) (string, bool) {
	if dirHasInstaller(src) {
		if a, err := filepath.Abs(src); err == nil {
			return a, true
		}
		return src, true
	}
	if fileExists(src) && os.MkdirAll(dst, 0o700) == nil {
		if exec.Command("tar", "-xzf", src, "-C", dst).Run() == nil || exec.Command("tar", "-xf", src, "-C", dst).Run() == nil {
			if dirHasInstaller(dst) {
				return dst, true
			}
			ds, _ := os.ReadDir(dst)
			for _, d := range ds {
				if p := filepath.Join(dst, d.Name()); d.IsDir() && dirHasInstaller(p) {
					return p, true
				}
			}
		}
	}
	Err("No install.sh found in '" + src + "' (pass a wattun-offline-<arch>.tar.gz archive or its extracted directory).")
	return "", false
}

// restartStale offers to restart tunnels still on the replaced binary and
// checks they switched.
func restartStale() bool {
	st := staleTunnels()
	if len(st) == 0 {
		Ok("All running tunnels use wattun " + BinVersion() + ".")
		return true
	}
	Warn("Still running the OLD binary: " + BOLD + strings.Join(st, " ") + RST)
	Hint("They switch to " + BinVersion() + " only after a restart. A restart drops open connections for a few seconds.")
	if !Confirm("Restart them now?", true) {
		Hint("Later: open the tunnel and restart it, or Tools → All tunnels → Restart all.")
		return true
	}
	for _, n := range st {
		step("Restarting "+Unit(n), func() bool { return autoForEachUnit(n, "restart") })
	}
	time.Sleep(time.Second)
	var bad []string
	for _, n := range st {
		if isStale(n) {
			bad = append(bad, n)
			continue
		}
		if IsAutoKharej(n) {
			for _, hu := range autoHelpers(n) {
				if IsActive(Unit(hu)) && isStale(hu) {
					bad = append(bad, n)
					break
				}
			}
		}
	}
	if len(bad) > 0 {
		Err("Still on the old binary: " + strings.Join(bad, " ") + " (see: journalctl -u " + P.Prefix + "@NAME)")
		return false
	}
	Ok("Tunnels now run wattun " + BinVersion() + ".")
	return true
}

// ---- roll back ----

func rollback() {
	prev := P.Bin + ".prev"
	if !fileExists(prev) {
		Warn("No previous version saved.")
		return
	}
	pv, _ := exec.Command(prev, "-version").CombinedOutput()
	Say("  Current: " + BOLD + BinVersion() + RST + "    Previous: " + BOLD + strings.TrimSpace(string(pv)) + RST)
	fmt.Fprintln(Stdout)
	if !Confirm("Roll back to the previous version?", false) {
		return
	}
	rb := P.Bin + ".rb"
	if copyFile(P.Bin, rb, 0o755) != nil || os.Rename(prev, P.Bin) != nil || os.Rename(rb, prev) != nil {
		Err("Roll back failed; check " + P.Bin + " and " + prev + ".")
		return
	}
	Ver = BinVersion()
	Ok("Rolled back: wattun is now " + BOLD + Ver + RST + ".")
	restartStale()
}

// ---- offline bundle ----

func bundleCmd(arch, out string) bool {
	if arch == "" {
		switch runtime.GOARCH {
		case "amd64", "arm64":
			arch = runtime.GOARCH
		default:
			Err("Specify architecture: " + P.Self + " bundle amd64  or  " + P.Self + " bundle arm64")
			return false
		}
	}
	if arch != "amd64" && arch != "arm64" {
		Err("Unsupported bundle architecture '" + arch + "' (use amd64 or arm64).")
		return false
	}
	if out == "" {
		wd, _ := os.Getwd()
		out = filepath.Join(wd, "wattun-offline-"+arch+".tar.gz")
	}
	updateProxyEnv()
	base := uURLPrefix + "https://github.com/" + repo() + "/releases/latest/download"
	bdir, err := os.MkdirTemp("", "wattun-bundle.*")
	if err != nil {
		Err("Cannot create a temporary directory.")
		return false
	}
	defer os.RemoveAll(bdir)
	sub := filepath.Join(bdir, "wattun-offline-"+arch)
	_ = os.MkdirAll(sub, 0o755)
	files := []string{"install.sh", "wattun-linux-" + arch, "wattun-manager", "SHA256SUMS", "SHA256SUMS.sig"}
	if err := spin("Downloading release files for linux/"+arch, func() error {
		for _, f := range files {
			if err := download(filepath.Join(sub, f), base+"/"+f); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		Err("Download failed from " + base + ".")
		return false
	}
	sums, _ := os.ReadFile(filepath.Join(sub, "SHA256SUMS"))
	sig, _ := os.ReadFile(filepath.Join(sub, "SHA256SUMS.sig"))
	if !sumsVerify(sums, sig, "") {
		Err("Signature check on SHA256SUMS failed; refusing to create an unverified bundle.")
		return false
	}
	for _, f := range files[:3] {
		if !sumsHas(sums, f, fileSHA(filepath.Join(sub, f))) {
			Err("Checksum mismatch for " + f + " in SHA256SUMS; aborting.")
			return false
		}
		_ = os.Chmod(filepath.Join(sub, f), 0o755)
	}
	if outB, err := exec.Command("tar", "-czf", out, "-C", bdir, "wattun-offline-"+arch).CombinedOutput(); err != nil {
		Err("Failed to write archive '" + out + "': " + strings.TrimSpace(string(outB)))
		return false
	}
	Ok("Verified offline bundle written: " + BOLD + out + RST)
	Hint("1. Copy to Iran:   scp \"" + out + "\" root@IRAN_IP:/root/")
	Hint("2. Fresh install:  tar xzf /root/" + filepath.Base(out) + " -C /root && bash /root/wattun-offline-" + arch + "/install.sh")
	Hint("3. Offline update: wattun update --from /root/" + filepath.Base(out))
	return true
}

// ---- uninstall ----

func kreplyConf() string { return "/etc/sysctl.d/90-" + P.Prefix + "-reverse.conf" }

func kreplyRestore() {
	if !fileExists(kreplyConf()) {
		return
	}
	_ = os.Remove(kreplyConf())
	orig := filepath.Join(P.Conf, ".kreply.orig")
	if fileExists(orig) && exec.Command("sysctl", "-q", "-p", orig).Run() == nil {
		_ = os.Remove(orig)
	}
	Ok("Restored the kernel's normal ping replies (no ICMP tunnel that needs it is left).")
}

func listUnits(patterns ...string) []string {
	out, _ := exec.Command("systemctl", append([]string{"list-units", "--all", "--plain", "--no-legend"}, patterns...)...).Output()
	var us []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			us = append(us, f[0])
		}
	}
	return us
}

func uninstallAll() bool {
	list := TunnelsAll()
	fmt.Fprintln(Stdout)
	if len(list) > 0 {
		Warn("These tunnels will be stopped:")
		for _, n := range list {
			fmt.Fprintf(Stdout, "      %s%-14s%s %s · %s\n", BOLD, n, RST, Role(n), Cfg(n, "carrier"))
		}
	} else {
		Hint("No tunnels are configured.")
	}
	fmt.Fprintln(Stdout)
	ans := "uninstall"
	if !NonInteractive {
		ans = Ask("Type 'uninstall' to remove WatTunnel (empty = cancel)", "")
	}
	if ans != "uninstall" {
		Warn("Cancelled.")
		return false
	}
	old := Stdout
	Stdout = io.Discard
	healDisable()
	Stdout = old
	units := map[string]bool{}
	for _, u := range listUnits(P.Prefix + "@*") {
		units[u] = true
	}
	for _, n := range list {
		units[Unit(n)+".service"] = true
	}
	for u := range units {
		_ = Systemctl("disable", "--now", u)
	}
	for _, n := range list {
		if !isAutoExt(n) {
			continue
		}
		if p := lastColon(Cfg(n, "listen")); p != "" && isShapedUDP(Cfg(n, "carrier")) {
			fwClose(p + "/udp")
		}
	}
	kreplyRestore()
	for _, pat := range []string{"-bondretest-*.service", "-bondretest-*.timer"} {
		fs, _ := filepath.Glob("/etc/systemd/system/" + P.Prefix + pat)
		for _, f := range fs {
			_ = Systemctl("disable", "--now", filepath.Base(f))
			_ = os.Remove(f)
		}
	}
	for _, u := range listUnits(P.Prefix+"-autowatch-*", P.Prefix+"-autoretest-*", P.Prefix+"-matrix-*") {
		_ = Systemctl("stop", u)
		_ = Systemctl("reset-failed", u)
	}
	for _, n := range list {
		for _, f := range stateFiles(n) {
			_ = os.Remove(f)
		}
	}
	for _, f := range []string{"/etc/systemd/system/" + P.Prefix + "@.service", P.Bin, P.Bin + ".prev"} {
		_ = os.Remove(f)
	}
	optDir := "/opt/" + P.Prefix
	if P.Sandbox {
		_ = os.RemoveAll(P.Run)
		_ = os.RemoveAll(envOr("WAT_AUTO_RUN", "/run/"+P.Prefix+"-auto"))
		if filepath.Dir(P.Bin) == optDir {
			_ = os.RemoveAll(optDir)
			Ok("Removed " + optDir)
		}
	}
	_ = Systemctl("daemon-reload")
	Ok("Services and binaries removed.")
	if fileExists(P.Conf) && Confirm("Also delete "+P.Conf+" (tunnel configs, keys, tokens)?", P.Sandbox || NonInteractive) {
		_ = os.RemoveAll(P.Conf)
		Ok("Configuration deleted.")
	}
	Ok("WatTunnel removed.")
	if P.Sandbox {
		if filepath.Dir(P.Mgr) == optDir {
			_ = os.RemoveAll(optDir)
			Ok("Removed " + optDir + " (including the manager)")
		} else {
			Hint("Sandbox: the manager (" + P.Mgr + ") was left in place; delete it by hand if you copied it.")
		}
	} else {
		_ = os.Remove(P.Mgr)
	}
	return true
}

// ---- auto-heal (run every minute by the heal timer; plain text, no colour) ----

func readInt(p string) int {
	b, _ := os.ReadFile(p)
	return atoi(strings.TrimSpace(string(b)))
}

func writeInt(p string, v int) { _ = os.WriteFile(p, []byte(strconv.Itoa(v)+"\n"), 0o644) }

func rmAll(ps ...string) {
	for _, p := range ps {
		_ = os.Remove(p)
	}
}

// recent: p was touched within d.
func recent(p string, d time.Duration) bool {
	fi, err := os.Stat(p)
	return err == nil && time.Since(fi.ModTime()) < d
}

// runEnvArgs are the --setenv arguments a transient heal unit needs.
func runEnvArgs() []string {
	a := []string{"--setenv=WAT_CONF=" + P.Conf, "--setenv=WAT_RUN=" + P.Run, "--setenv=WAT_PREFIX=" + P.Prefix}
	if os.Getenv("WAT_BIN") != "" || P.Sandbox {
		a = append(a, "--setenv=WAT_BIN="+P.Bin)
	}
	for _, k := range []string{"WAT_AUTO_RUN", "WAT_GO_MGR"} {
		if v := os.Getenv(k); v != "" {
			a = append(a, "--setenv="+k+"="+v)
		}
	}
	return a
}

// healSpawn runs the manager with args in a transient unit at most once per
// every window, so the work outlives this heal pass.
func healSpawn(stamp string, every time.Duration, unit string, extra []string, args ...string) {
	if recent(stamp, every) {
		return
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return
	}
	_ = os.WriteFile(stamp, nil, 0o644)
	a := append([]string{"--quiet", "--collect", "--unit", unit}, runEnvArgs()...)
	a = append(append(a, extra...), P.Mgr)
	_ = exec.Command("systemd-run", append(a, args...)...).Run()
}

func healRetest(n string) {
	envLogger("wattun-heal", "tunnel "+n+" still down after restarts, testing the other connection types")
	healSpawn(filepath.Join(P.Run, n+".retest"), 30*time.Minute, P.Prefix+"-autoretest-"+n, nil, "auto-retest", n, "--yes")
}

func healMatrix(n string) {
	envLogger("wattun-heal", "tunnel "+n+" still down after 3 restart cycles, running the anti-censor matrix")
	healSpawn(filepath.Join(P.Run, n+".matrix"), time.Hour, P.Prefix+"-matrix-"+n, []string{"--setenv=AC_FALLBACK=1"}, "matrix", n, "--yes")
}

func cdnTunnelP(n string) bool {
	return Role(n) == "Iran" && !IsReverse(n) && isCDNCarrier(Cfg(n, "carrier")) && Cfg(n, "sni")+Cfg(n, "host") != ""
}

func healAutoHelpers(parent string) {
	if !IsAutoKharej(parent) || !IsEnabled(Unit(parent)) || !IsActive(Unit(parent)) {
		return
	}
	for _, u := range autoHelpers(parent) {
		if !IsEnabled(Unit(u)) {
			_ = Systemctl("enable", Unit(u))
		}
		if !IsActive(Unit(u)) {
			envLogger("wattun-heal", "auto helper "+u+" is down, restarting")
			_ = Systemctl("restart", Unit(u))
		}
	}
}

// slaFile reads the key=value SLA limits of a tunnel.
func slaVal(f, key string) int {
	b, _ := os.ReadFile(f)
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return atoi(strings.TrimSpace(v))
		}
	}
	return 0
}

// heal restarts Iran tunnels that stay down 3 checks in a row, tracks SLA
// breaches, escalates to a retest or the matrix, and keeps auto Kharej helpers
// running.
func heal() {
	_ = os.MkdirAll(P.Run, 0o755)
	for _, n := range Tunnels() {
		if Role(n) != "Iran" || !IsEnabled(Unit(n)) {
			continue
		}
		f := filepath.Join(P.Run, n+".down")
		cyc := filepath.Join(P.Run, n+".cycles")
		bf := filepath.Join(P.Run, n+".sla_breach")
		sb := filepath.Join(P.Run, n+".sla_bytes")
		// no metrics: nothing to judge by, never count it as down
		if Cfg(n, "metrics") == "" || !IsActive(Unit(n)) && ShowProp(Unit(n), "ActiveState") == "inactive" {
			rmAll(f, cyc, bf, sb)
			continue
		}
		m, _ := p1Stats(n)
		age := -1.0
		if m != nil && get(m, "last_rx_age_ms") != "" {
			age = getF(m, "last_rx_age_ms")
		}
		if m != nil && get(m, "alive") == "true" && age >= 0 && age < 35000 {
			rmAll(f, cyc)
			healSLA(n, m, bf, sb)
			continue
		}
		cnt := readInt(f) + 1
		writeInt(f, cnt)
		if cnt < 3 {
			continue
		}
		envLogger("wattun-heal", fmt.Sprintf("tunnel %s down for %d checks, restarting", n, cnt))
		_ = Systemctl("restart", Unit(n))
		_ = os.Remove(f)
		c := readInt(cyc) + 1
		writeInt(cyc, c)
		cr := Cfg(n, "carrier")
		if c >= 2 && !IsReverse(n) && IsPoolList(cr) && Cfg(n, "fake-sni") == "" {
			envLogger("wattun-heal", "tunnel "+n+": restarts do not fix it and it runs with no anti-censor; if the route is being filtered, run: wattun blackout "+n+" <allowlisted-name>")
		}
		if c >= 3 && !IsReverse(n) && (IsPool(cr) || cr == "icmp") {
			healMatrix(n)
		}
		if c >= 2 && (fileExists(filepath.Join(P.Conf, n+".auto")) || BinVerOK("2.2.0") && cdnTunnelP(n)) {
			healRetest(n)
		}
	}
	autoMigrateAll(false)
	for _, n := range Tunnels() {
		if Role(n) == "Kharej" && IsAutoKharej(n) {
			autoSyncCompanion(n)
			healAutoHelpers(n)
		}
	}
}

// healSLA counts consecutive SLA breaches of a live tunnel (rtt, loss, or the
// measured rate while streams are open) and retests an auto tunnel after 3.
func healSLA(n string, m map[string]any, bf, sb string) {
	sf := filepath.Join(P.Conf, n+".sla")
	if !fileExists(sf) {
		return
	}
	minR, maxRTT, maxLoss := slaVal(sf, "sla_min_rate_kbps"), slaVal(sf, "sla_max_rtt_ms"), slaVal(sf, "sla_max_loss_pct")
	rtt := getF(m, "rtt_ms")
	if rtt == 0 {
		rtt = getF(m, "srtt_ms")
	}
	loss := getF(m, "loss_pct")
	tot := getF(m, "bytes_in_total") + getF(m, "bytes_out_total")
	now := time.Now().Unix()
	rate := -1
	if b, err := os.ReadFile(sb); err == nil {
		var pt float64
		var pn int64
		if _, err := fmt.Sscan(string(b), &pt, &pn); err == nil && tot >= pt && now > pn {
			rate = int((tot - pt) * 8 / 1000 / float64(now-pn))
		}
	}
	_ = os.WriteFile(sb, []byte(fmt.Sprintf("%.0f %d\n", tot, now)), 0o644)
	act := getIFlat(m, "streams_total", "streams")
	breached := maxRTT > 0 && int(rtt) > maxRTT || maxLoss > 0 && int(loss) > maxLoss ||
		minR > 0 && rate >= 0 && act > 0 && rate < minR
	if !breached {
		_ = os.Remove(bf)
		return
	}
	c := readInt(bf) + 1
	writeInt(bf, c)
	if c < 3 {
		return
	}
	envLogger("wattun-heal", fmt.Sprintf("tunnel %s breached SLA for 3 consecutive checks (rtt=%.1fms, loss=%.1f%%, rate=%dkbps), triggering re-evaluation", n, rtt, loss, rate))
	_ = os.Remove(bf)
	_ = os.WriteFile(filepath.Join(P.Run, n+".sla_triggered"), nil, 0o644)
	if fileExists(filepath.Join(P.Conf, n+".auto")) {
		healRetest(n)
	}
}
