package panel

// One-step pairing (3.6.1): Kharej shows its pairing token (made on first use), Iran adds a Kharej with it
// (`wattun add-kharej`), and a Kharej added that way can be removed again. Making a link tests carriers and
// takes a minute or more, so the writes run as manager jobs; the page follows them like any job.

import (
	"net/http"
	"strings"
)

// apiPairing: who this Kharej is paired with and whether its token exists (the token itself is a secret: POST).
func (s *Server) apiPairing(c *call) {
	tok, state := s.be.Pairing()
	c.ok(map[string]any{"made": tok != "", "state": state, "role": s.be.Host().Role})
}

// apiPairingMake: action show (the token, full tier like Show token), make (first time) or rotate.
func (s *Server) apiPairingMake(c *call) {
	var in struct{ Action string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	if role := s.be.Host().Role; role == "iran" {
		c.fail(http.StatusConflict, "This is the Iran server; the pairing token is made on Kharej.")
		return
	}
	switch in.Action {
	case "show":
		tok, state := s.be.Pairing()
		s.audit(c, "pairing token shown", "", "ok")
		c.ok(map[string]any{"token": tok, "state": state})
	case "make", "rotate":
		args := []string{"pair-token", "--yes"}
		title := "Pairing token"
		if in.Action == "rotate" {
			args, title = []string{"pair-token", "--rotate", "--yes"}, "New pairing token"
		}
		id, err := s.jobs.run("pair", title, c.sess.User, s.be.ManagerArgv(args...))
		s.jobReply(c, "pairing token "+in.Action, "", id, err)
	default:
		c.fail(http.StatusBadRequest, "action is show, make or rotate")
	}
}

// apiKharejAdd: pair this Iran with the Kharej that printed TOKEN.
func (s *Server) apiKharejAdd(c *call) {
	var in struct{ Token, Test string }
	if c.json(&in) != nil {
		c.fail(http.StatusBadRequest, "bad request")
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	if !strings.HasPrefix(in.Token, "wat1:") || strings.ContainsAny(in.Token, " \n\t") {
		c.fail(http.StatusBadRequest, "Paste the pairing token Kharej shows (it starts with wat1:).")
		return
	}
	if !testPresets[in.Test] {
		c.fail(http.StatusBadRequest, "unknown test preset")
		return
	}
	if s.be.Host().Role == "kharej" {
		c.fail(http.StatusConflict, "This is a Kharej server; add Kharej servers on the Iran server.")
		return
	}
	args := []string{"add-kharej", "--token", in.Token}
	if in.Test != "" {
		args = append(args, "--test", in.Test)
	}
	id, err := s.jobs.run("pair", "Add Kharej", c.sess.User, s.be.ManagerArgv(append(args, "--yes")...))
	s.jobReply(c, "add kharej", "", id, err)
}

// apiKharejRemove: drop the pairing link to HOST. The tunnels to it keep running.
func (s *Server) apiKharejRemove(c *call) {
	for _, k := range s.kharejSnap() {
		if k.Host != c.arg[0] {
			continue
		}
		if k.Link == "" {
			c.fail(http.StatusConflict, "This Kharej is paired through a tunnel of its own ("+strings.Join(k.Via, ", ")+"): forget the pairing in that tunnel's drawer.")
			return
		}
		id, err := s.jobs.run("pair", "Remove Kharej "+k.Host, c.sess.User, s.be.ManagerArgv("remove-kharej", k.Host, "--yes"))
		s.jobReply(c, "remove kharej", k.Host, id, err)
		s.refreshKharej()
		return
	}
	c.fail(http.StatusNotFound, "no such Kharej server")
}
