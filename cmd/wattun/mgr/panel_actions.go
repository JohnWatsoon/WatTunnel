package mgr

// TTY-free entry points for the web panel (cmd/wattun/panel_backend.go). Each one is the console's own logic
// with the prompts taken out: the panel asks its questions in the browser, then calls these. Nothing here
// prints (AGENTS.md: logic lives in TTY-free functions; managers and panel only call them).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// KharejCall runs one pairing command through local tunnel VIA. Writes get a fresh id and, when Kharej judges
// it, the current base_seq (one retry when Kharej changed in between). refused is the console's plain-words
// refusal ("Kharej refused it (code N): ...") and is "" on success; err is a channel failure.
func KharejCall(via, cmd string, args map[string]any) (params map[string]any, refused string, err error) {
	cl, err := scepterDial(via)
	if err != nil {
		return nil, "", err
	}
	if args == nil {
		args = map[string]any{}
	}
	write := kharejWrites[cmd]
	for try := 0; ; try++ {
		if write {
			args["id"] = scepterNewID()
			if _, has := args["ttl_s"]; !has {
				args["ttl_s"] = scepterTTLDefault
			}
			if doc, derr := scepterFetchDoc(cl); derr == nil {
				args["base_seq"] = doc.StateSeq
			}
		}
		res, err := cl.Call(cmd, args)
		if err != nil {
			return nil, "", err
		}
		if res.Code == scepterCodeOK {
			return res.Params, "", nil
		}
		if res.Code == scepterCodeStale && try == 0 {
			continue
		}
		return res.Params, KharejRefusal(res.Code, res.Params), nil
	}
}

var kharejWrites = map[string]bool{"tunnel.create": true, "tunnel.edit": true, "tunnel.delete": true,
	"tunnel.start": true, "tunnel.stop": true, "tunnel.restart": true, "limits.set": true, "limits.reset": true,
	"preset.apply": true, "tunnel.keyrotate": true, "carrier.mute": true, "carrier.change": true, "auto.apply": true,
	"update.run": true}

// KharejRefusal is scepterCodeErr's text on one line.
func KharejRefusal(code int, p map[string]any) string {
	s := fmt.Sprintf("Kharej refused it (code %d)", code)
	if h := scepterCodeHint(code, p); h != "" {
		s += ": " + h
	}
	if d, _ := p["detail"].(string); d != "" {
		s += " (Kharej: " + d + ")"
	}
	return s
}

// KharejKeyRotate rotates remote tunnel NAME's key through VIA and rewrites this server's twin of it (the local
// Iran tunnel with the same name that dials the same host), then restarts the twin. local is "" when no twin
// exists here; token is the new token either way (for another Iran server).
func KharejKeyRotate(via, name string) (local, token string, err error) {
	p, refused, err := KharejCall(via, "tunnel.keyrotate", map[string]any{"name": name})
	if err != nil {
		return "", "", err
	}
	if refused != "" {
		return "", "", fmt.Errorf("%s", refused)
	}
	token, _ = p["token"].(string)
	if token == "" {
		return "", "", fmt.Errorf("Kharej rotated the key but sent no token: read it on Kharej's console")
	}
	// the twin: same name and same Kharej host (the console's rule); else the only tunnel here dialing that host
	host := scepterPeerHost(via)
	if fileExists(filepath.Join(P.Conf, name+".yml")) && Role(name) == "Iran" && host != "" && scepterPeerHost(name) == host {
		local = name
	} else if c := scepterSameHost(host); host != "" && len(c) == 1 {
		local = c[0]
	}
	if local == "" {
		return "", token, nil
	}
	if _, err := scepterRotateLocalToken(local, token); err != nil {
		return local, token, fmt.Errorf("Kharej is on the new key, but rewriting %s here failed: %v", local, err)
	}
	scepterRotMark(local)
	if err := Restart(Unit(local)); err != nil {
		return local, token, fmt.Errorf("%s has the new key but did not restart: %v", local, err)
	}
	return local, token, nil
}

func scepterSameHost(host string) []string {
	var out []string
	for _, n := range ManagedTunnels() {
		if Role(n) == "Iran" && PairHost(n) == host {
			out = append(out, n)
		}
	}
	return out
}

// KharejBackup unpacks a backup.export answer into the verified tarball.
func KharejBackup(p map[string]any) ([]byte, error) {
	docs := scepterLogsOf(p)
	if len(docs) != 1 {
		return nil, fmt.Errorf("Kharej sent %d backup files, want exactly 1", len(docs))
	}
	_, raw, err := scepterParseBackupDoc(docs[0])
	return raw, err
}

// SpeedResult is one direction of the built-in speed test.
type SpeedResult struct {
	Dir     string  `json:"dir"`
	OK      bool    `json:"ok"`
	MBps    float64 `json:"mb_per_s"`
	Seconds float64 `json:"seconds"`
	Error   string  `json:"error,omitempty"`
}

// SpeedTestOnce runs the tunnel's /speedtest one way (dir down|up) with mb megabytes.
func SpeedTestOnce(name, dir string, mb int) (SpeedResult, error) {
	if Role(name) != "Iran" {
		return SpeedResult{}, fmt.Errorf("the speed test runs from the Iran side")
	}
	m := Cfg(name, "metrics")
	if m == "" {
		return SpeedResult{}, fmt.Errorf("the speed test needs metrics: in %s.yml", name)
	}
	r, err := fetchSpeedtest(m, dir, mb)
	if err != nil {
		return SpeedResult{}, fmt.Errorf("no answer from the tunnel: %v", err)
	}
	return SpeedResult{Dir: dir, OK: r.OK, MBps: r.MBPerS, Seconds: r.Seconds, Error: r.Error}, nil
}

// SetPorts replaces NAME's port mappings after the console's own validation (NormSpec). Ports hot-reload.
func SetPorts(name string, specs []string) error {
	var maps []string
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := NormSpec(s)
		if err != nil {
			return fmt.Errorf("%q: %v (examples: 443, 8443:443, 53/udp)", s, err)
		}
		maps = append(maps, n...)
	}
	if len(maps) == 0 {
		return fmt.Errorf("a tunnel needs at least one port")
	}
	return WritePorts(name, maps)
}

// SetPortLimit writes one limits: row (the console's set_port_limit): rate like 10mbit, quota like 50G, period
// day|week|month. Empty or 0 rate and quota remove the row. Limits hot-reload.
func SetPortLimit(name, port, rate, quota, period string) error {
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("port %q is not a number", port)
	}
	switch period {
	case "", "day", "week", "month":
	default:
		return fmt.Errorf("period is day, week or month")
	}
	for _, v := range []string{rate, quota} {
		if strings.ContainsAny(v, " \t\n:#") {
			return fmt.Errorf("%q is not a rate or quota", v)
		}
	}
	f := filepath.Join(P.Conf, name+".yml")
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	return atomicWrite(f, []byte(setPortLimitYAML(string(b), port, rate, quota, period)), 0o600)
}

// KharejCreate creates tunnel NAME (empty: Kharej picks) on Kharej through VIA, carrying CARRIER and allowing the
// target PORTS ("18999,2000"), and returns the token for this side.
func KharejCreate(via, name, carrier, ports string) (string, error) {
	p, refused, err := KharejCall(via, "tunnel.create", scepterCreateArgs(name, carrier, ports, nil, 0, ""))
	if err != nil {
		return "", err
	}
	if refused != "" {
		return "", fmt.Errorf("%s", refused)
	}
	tok := scepterCreatedToken(via, p, nil)
	if tok == "" {
		return "", fmt.Errorf("Kharej made the tunnel but its token could not be built here: read it on Kharej's console (token NAME)")
	}
	return tok, nil
}

// TokenOf is NAME's saved token ("" when there is none).
func TokenOf(name string) string {
	b, _ := os.ReadFile(filepath.Join(P.Conf, name+".token"))
	return strings.TrimSpace(string(b))
}

// KharejPairRotate asks Kharej for a new pairing credential (pair.rotate, the old one stays valid for 5 minutes)
// and attaches it to every local tunnel paired with that host, restarting each so it uses the new one.
func KharejPairRotate(via []string) error {
	if len(via) == 0 {
		return fmt.Errorf("no tunnel to that server")
	}
	p, refused, err := KharejCall(via[0], "pair.rotate", map[string]any{"window_s": 300})
	if err != nil {
		return err
	}
	if refused != "" {
		return fmt.Errorf("%s", refused)
	}
	line, _ := p["watp1"].(string)
	if line == "" {
		return fmt.Errorf("Kharej answered without a new credential")
	}
	for _, n := range via {
		if err := scepterPairTo(n, line); err != nil {
			return fmt.Errorf("%s: %v (Kharej already has the new credential; the old one works for 5 minutes)", n, err)
		}
		if IsActive(Unit(n)) {
			_ = Restart(Unit(n))
		}
	}
	return nil
}

// PairForget turns the pairing channel of a local tunnel off (`pairing: false`, the explicit off switch) and
// restarts it. Kharej keeps its side; it is managed from its own console until a new pairing is attached.
func PairForget(name string) error {
	if err := SetValue(name, "pairing", "false"); err != nil {
		return err
	}
	if IsActive(Unit(name)) {
		return Restart(Unit(name))
	}
	return nil
}

// PanelFirewall opens the panel's new port and, after it, closes the old one (port change from the panel).
func PanelFirewall(open, close int) {
	if open > 0 {
		fwOpen(strconv.Itoa(open) + "/tcp")
	}
	if close > 0 && close != open {
		fwClose(strconv.Itoa(close) + "/tcp")
	}
}

// LatestVersion is the newest release tag ("3.6.1"), read from the releases/latest redirect through the update
// proxy; "" when GitHub cannot be reached.
func LatestVersion() string {
	updateProxyEnv()
	cl := updClient()
	cl.Timeout = 20 * time.Second
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r, err := cl.Get(uURLPrefix + "https://github.com/" + repo() + "/releases/latest")
	if err != nil {
		return ""
	}
	r.Body.Close()
	loc := r.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/v")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(loc[i+len("/tag/v"):])
}

// PathInfo is one leg of a bonded tunnel as its /stats reports it.
type PathInfo struct {
	Name, RTT, Loss, Share string
	Alive, Muted           bool
}

// BondPaths: the bond mode and the live legs of a tunnel (no legs when it is stopped or has one carrier).
func BondPaths(n string) (mode string, out []PathInfo) {
	for _, c := range tinfo(n).Cars {
		out = append(out, PathInfo{Name: c.Name, RTT: c.RTT, Loss: c.Loss, Share: c.Share, Alive: c.Alive == "true", Muted: c.Muted == "true"})
	}
	return orStr(Cfg(n, "bond-mode"), "balanced"), out
}

// GeoLookup asks a public IP-location service where ADDR (an IP or a host name) is, through the update proxy.
// ipwho.is first, ipapi.co when it fails. Only the address is sent.
func GeoLookup(addr string) (lat, lon float64, cc, city string, err error) {
	ip := addr
	if net.ParseIP(addr) == nil {
		ips, lerr := net.LookupIP(addr)
		if lerr != nil || len(ips) == 0 {
			return 0, 0, "", "", fmt.Errorf("cannot resolve %s", addr)
		}
		ip = ips[0].String()
	}
	updateProxyEnv()
	cl := updClient()
	cl.Timeout = 12 * time.Second
	var out struct {
		Success     *bool   `json:"success"` // ipwho.is
		Error       bool    `json:"error"`   // ipapi.co
		Lat         float64 `json:"latitude"`
		Lon         float64 `json:"longitude"`
		CountryCode string  `json:"country_code"`
		City        string  `json:"city"`
	}
	for _, u := range []string{"https://ipwho.is/" + ip, "https://ipapi.co/" + ip + "/json/"} {
		r, gerr := cl.Get(u)
		if gerr != nil {
			err = gerr
			continue
		}
		out.Success, out.Error, out.CountryCode = nil, false, ""
		derr := json.NewDecoder(r.Body).Decode(&out)
		r.Body.Close()
		if derr == nil && !out.Error && (out.Success == nil || *out.Success) && out.CountryCode != "" {
			return out.Lat, out.Lon, out.CountryCode, out.City, nil
		}
		err = fmt.Errorf("%s gave no location for %s", u[:strings.Index(u[8:], "/")+8], ip)
	}
	return 0, 0, "", "", err
}
