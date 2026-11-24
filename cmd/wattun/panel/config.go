// Package panel is the web panel (`wattun -panel FILE`, plan docs/handoff/PLAN-panel.md, 3.6.0): a public HTTPS
// server on the Iran host behind a secret path, password + optional TOTP login, that shows this server's tunnels
// and the paired Kharej servers. Phase 1 is read-only: it never writes a tunnel config or touches a unit; the only
// file it writes is its own config (password, 2FA). Every action it will gain later calls the manager's functions
// or a scepter command — it never re-implements tunnel logic (AGENTS.md, "Every feature reaches every surface").
package panel

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is panel.conf. It is NOT a .yml on purpose: the managers list every $CONF/*.yml as a tunnel.
type Config struct {
	Port     int
	Path     string // secret path segment, no slashes
	Title    string // page title and TOTP issuer; never the product name (no fingerprints)
	User     string
	PassHash string // bcrypt
	TOTP     string // base32 secret; "" = 2FA off
	TOTPLast int64  // last accepted time step (replay guard)
	Recovery []string
	CertFile string
	KeyFile  string
	file     string
}

// LoadConfig reads FILE. Unknown keys are ignored so an older binary reads a newer file.
func LoadConfig(file string) (*Config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	c := &Config{file: file}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "port":
			c.Port, _ = strconv.Atoi(v)
		case "path":
			c.Path = v
		case "title":
			c.Title = v
		case "user":
			c.User = v
		case "pass":
			c.PassHash = v
		case "totp":
			c.TOTP = v
		case "totp-last":
			c.TOTPLast, _ = strconv.ParseInt(v, 10, 64)
		case "recovery":
			if v != "" {
				c.Recovery = strings.Split(v, ",")
			}
		case "cert":
			c.CertFile = v
		case "cert-key":
			c.KeyFile = v
		}
	}
	if c.Port < 1 || c.Port > 65535 || len(c.Path) < 8 || c.User == "" || c.PassHash == "" {
		return nil, fmt.Errorf("%s: port, path (8+ chars), user and pass are required", file)
	}
	dir := filepath.Dir(file)
	if c.CertFile == "" {
		c.CertFile = filepath.Join(dir, ".panel.crt")
	}
	if c.KeyFile == "" {
		c.KeyFile = filepath.Join(dir, ".panel.key")
	}
	return c, nil
}

// Save writes the config atomically with mode 0600 (it holds the password hash and the TOTP secret).
func (c *Config) Save() error { return c.SaveAs(c.file) }

func (c *Config) SaveAs(file string) error {
	c.file = file
	var b strings.Builder
	b.WriteString("# web panel (wattun -panel). Managed by `wattun panel ...`; edit by hand only with the panel stopped.\n")
	fmt.Fprintf(&b, "port: %d\npath: %s\ntitle: %s\nuser: %s\npass: %s\n", c.Port, c.Path, c.Title, c.User, c.PassHash)
	fmt.Fprintf(&b, "totp: %s\ntotp-last: %d\nrecovery: %s\n", c.TOTP, c.TOTPLast, strings.Join(c.Recovery, ","))
	dir := filepath.Dir(file)
	if c.CertFile != "" && c.CertFile != filepath.Join(dir, ".panel.crt") {
		fmt.Fprintf(&b, "cert: %s\n", c.CertFile)
	}
	if c.KeyFile != "" && c.KeyFile != filepath.Join(dir, ".panel.key") {
		fmt.Fprintf(&b, "cert-key: %s\n", c.KeyFile)
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}
