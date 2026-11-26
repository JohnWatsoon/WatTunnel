package panel

// Phase 4: panel settings (title, secret path, IP allowlist) and the certificate tiers (tls.go).

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func (s *Server) apiSettings(c *call) {
	cfg := s.conf()
	c.ok(map[string]any{
		"title": cfg.Title, "path": cfg.Path, "port": cfg.Port, "allow": nonNil(cfg.Allow), "your_ip": c.ip,
		"cert": certInfo(cfg),
		"alerts": map[string]any{"loss": cfg.AlertLoss, "disk": cfg.AlertDisk, "ram": cfg.AlertRAM,
			"speed_every": cfg.SpeedEvery, "backup_every": cfg.BackupEvery, "keep": cfg.BackupKeep},
	})
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// allowed reports whether IP may see the panel at all (empty allowlist = everyone).
func allowed(list []string, ip string) bool {
	if len(list) == 0 {
		return true
	}
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	for _, e := range list {
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(a) {
				return true
			}
		} else if b := net.ParseIP(e); b != nil && b.Equal(a) {
			return true
		}
	}
	return false
}

// apiSettingsPanel changes the title, the secret path and the allowlist. A path change answers the new address
// first; the old one stops working at once. An allowlist that would lock the caller out is refused.
func (s *Server) apiSettingsPanel(c *call) {
	var in struct {
		Title string
		Path  string
		Port  int
		Allow []string
	}
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" || len(in.Title) > 60 || strings.ContainsAny(in.Title, "<>\"\n") {
		c.fail(http.StatusBadRequest, "Title: 1-60 characters, no < > or quotes.")
		return
	}
	if strings.Contains(strings.ToLower(in.Title), "wattun") || strings.Contains(strings.ToLower(in.Title), "wattunnel") {
		c.fail(http.StatusBadRequest, "The title must not name the tunnel software: it shows before sign-in and in the 2FA app.")
		return
	}
	if len(in.Path) < 16 || len(in.Path) > 64 || strings.Trim(in.Path, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		c.fail(http.StatusBadRequest, "Secret path: 16-64 letters, digits, - or _.")
		return
	}
	cur := s.conf().Port
	if in.Port == 0 {
		in.Port = cur
	}
	if err := checkPort(in.Port, cur); err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return
	}
	var allow []string
	for _, e := range in.Allow {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		_, _, cerr := net.ParseCIDR(e)
		if cerr != nil && net.ParseIP(e) == nil {
			c.fail(http.StatusBadRequest, e+" is not an IP or a range like 5.6.7.0/24.")
			return
		}
		allow = append(allow, e)
	}
	if !allowed(allow, c.ip) {
		c.fail(http.StatusBadRequest, "This list would lock you out: add your own address ("+c.ip+").")
		return
	}
	s.cfgMu.Lock()
	s.cfg.Title, s.cfg.Allow = in.Title, allow
	moved := s.cfg.Path != in.Path
	s.cfg.Path = in.Path
	s.cfg.Port = in.Port
	err := s.cfg.Save()
	s.cfgMu.Unlock()
	s.audit(c, "panel settings", "", errText(err))
	if err != nil {
		c.fail(http.StatusInternalServerError, err.Error())
		return
	}
	if in.Port != cur {
		s.movePanel(cur, in.Port)
	}
	c.ok(map[string]any{"ok": true, "moved": moved || in.Port != cur, "path": in.Path, "port": in.Port, "port_changed": in.Port != cur})
}

// certChange runs FN on the config, saves it and loads the new pair into the listener.
func (s *Server) certChange(c *call, action string, fn func(cfg *Config) error) {
	s.cfgMu.Lock()
	old := *s.cfg
	err := fn(s.cfg)
	if err == nil {
		err = s.certs.load(s.cfg.CertFile, s.cfg.KeyFile)
	}
	if err == nil {
		err = s.cfg.Save()
	}
	if err != nil {
		*s.cfg = old
		s.certs.load(old.CertFile, old.KeyFile)
	}
	info := certInfo(s.cfg)
	s.cfgMu.Unlock()
	s.audit(c, action, "", errText(err))
	if err != nil {
		c.fail(http.StatusBadRequest, err.Error())
		return
	}
	c.ok(map[string]any{"ok": true, "cert": info})
}

func (s *Server) apiCertOwner(c *call) {
	var in struct{ Cert, Key string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	s.certChange(c, "certificate: own", func(cfg *Config) error { return useOwnerCert(cfg, []byte(in.Cert), []byte(in.Key)) })
}

func (s *Server) apiCertSelf(c *call) {
	s.certChange(c, "certificate: self-signed", useSelfSigned)
}

func (s *Server) apiCertCA(c *call) {
	s.certChange(c, "certificate: private CA", func(cfg *Config) error { return usePrivateCA(cfg, localIPs()) })
}

func (s *Server) apiCACert(c *call) {
	b, err := os.ReadFile(caFile(s.conf()))
	if err != nil {
		c.fail(http.StatusNotFound, "No private CA yet.")
		return
	}
	attach(c.w, "panel-ca.crt", "application/x-x509-ca-cert", b)
}

func (s *Server) apiCertACME(c *call) {
	var in struct{ Domain string }
	if c.json(&in) == nil && strings.TrimSpace(in.Domain) == "" {
		in.Domain = s.be.Host().IP // nothing typed: this server's own public IP, which the panel already knows
	}
	if strings.TrimSpace(in.Domain) == "" || strings.ContainsAny(in.Domain, " /\n") ||
		(strings.Contains(in.Domain, ":") && net.ParseIP(strings.TrimSpace(in.Domain)) == nil) {
		c.fail(http.StatusBadRequest, "Give the domain name that points at this server.")
		return
	}
	id, err := s.startACME(c.sess.User, strings.ToLower(strings.TrimSpace(in.Domain)))
	s.jobReply(c, "certificate: ACME", in.Domain, id, err)
}

// startACME runs the ACME issue as a job; the working certificate stays when it fails.
func (s *Server) startACME(user, domain string) (string, error) {
	return s.jobs.do("acme", "Certificate for "+domain, user, func(say func(string, ...any)) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		s.cfgMu.Lock()
		work := *s.cfg
		s.cfgMu.Unlock()
		if err := useACME(ctx, &work, domain, say); err != nil {
			say("The current certificate stays in use.")
			return err
		}
		if err := s.certs.load(work.CertFile, work.KeyFile); err != nil {
			return err
		}
		s.cfgMu.Lock()
		s.cfg.CertFile, s.cfg.KeyFile, s.cfg.CertKind, s.cfg.ACMEName = work.CertFile, work.KeyFile, work.CertKind, work.ACMEName
		err := s.cfg.Save()
		s.cfgMu.Unlock()
		if err == nil {
			// a browser that was told to accept the old self-signed certificate keeps saying "Not secure" for this
			// address until it restarts, although the new one is valid (checked 2026-11-26 with a fresh Chrome)
			say("Done. If the browser still says Not secure, close it fully and open the panel again: it remembers that you accepted the old certificate.")
		}
		return err
	})
}
