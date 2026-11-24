package mgr

// Pairing in one step (owner request 2026-11-24). Kharej shows one pairing token right after install, and again
// on the dashboard (t); Iran adds it with one action (Add Kharej, here and in the web panel). Under each pair
// sits a pairing link: a hidden auto tunnel that forwards nothing (one 127.0.0.1 port to Kharej port 1) and
// carries only the management channel. The owner's own tunnels are made through it (New tunnel, "on Kharej and
// here"), and their pages reach Kharej through it (scepterSameHost). The link's key file holds the whole token:
// that is what makes the engine derive the pairing on both ends (cmd/wattun/pairing.go parseTokenKey); a plain
// key file never pairs. Both servers need wattun 3.6.1.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const linkBase = "pair" // link names: pair, pair-2, ... (Kharej has one, Iran one per Kharej)

func init() {
	Register("pair_token_cmd", func(a ...string) int { return b2i(pairTokenCmd(hasFlag(a, "--rotate"))) })
	Register("add_kharej_cmd", func(a ...string) int { return b2i(addKharejCmd()) })
	Register("remove_kharej_cmd", func(a ...string) int { return b2i(removeKharejCmd(arg(a, 0))) })
}

// ServerSide is this server's role for the panel: "kharej", "iran", "mixed" or "" (not set and no tunnels).
func ServerSide() string { return serverSide() }

// PublicIPCached is this server's public address, looked up once in the background ("" until it is known).
func PublicIPCached() string { return cachedPublicIP() }

// freeLinkName: the first of pair, pair-2, ... whose config and helper names are all free.
func freeLinkName() string {
	taken := func(n string) bool {
		return fileExists(filepath.Join(P.Conf, n+".yml")) || fileExists(filepath.Join(P.Conf, n+"-r.yml")) || autoExtSpaceTaken(n)
	}
	n := linkBase
	for i := 2; taken(n) && i < 99; i++ {
		n = fmt.Sprintf("%s-%d", linkBase, i)
	}
	return n
}

// pskOf: the tunnel key in a key file's first line. A pairing link's key file holds the whole token, so the
// probes and token rebuilds that copy a key file take only its key field: a throw-away probe that carried the
// token would derive the pairing too and could claim it.
func pskOf(text string) string {
	s := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	if t, err := ReadToken(s); err == nil {
		return t.Key
	}
	return s
}

// pickLatchPort: the scepter latch port for a new Kharej config, 20443 unless EXCL or a listener here holds it
// (bash pick_latch_port; "" after 20499: the engine's key-derived default then applies).
func pickLatchPort(excl ...string) string {
next:
	for p := 20443; p <= 20499; p++ {
		for _, e := range excl {
			if e == strconv.Itoa(p) {
				continue next
			}
		}
		if !listenBlocked("tcp", p) {
			return strconv.Itoa(p)
		}
	}
	return ""
}

// ---- Kharej: the pairing token ----

// kharejLink is the Kharej-side link ("" when there is none yet).
func kharejLink() string {
	for _, n := range Links() {
		if Role(n) == "Kharej" {
			return n
		}
	}
	return ""
}

// PairingToken is the token Iran adds this Kharej with, making the link first when there is none.
func PairingToken() (string, error) {
	if n := kharejLink(); n != "" {
		if tok := TokenOf(n); tok != "" {
			return tok, nil
		}
		deleteQuiet(n) // a link without a token cannot pair anyone: make it again
	}
	if serverSide() == "iran" {
		return "", fmt.Errorf("this server is the Iran side; the pairing token is made on Kharej")
	}
	name := freeLinkName()
	r := wizardKharejAuto(name, autoWizardOpts{Name: name, Ports: "1", Link: true})
	if r.Error != nil {
		return "", r.Error
	}
	if err := writeFile0600(filepath.Join(P.Conf, name+".link"), "kharej\n"); err != nil {
		return "", err
	}
	return r.Token, nil
}

// RotatePairingToken makes a new pairing token: the link is made again with a new key and the pairing is opened,
// so the old token stops working and the Iran server paired before has to add this Kharej again.
func RotatePairingToken() (string, error) {
	if n := kharejLink(); n != "" {
		deleteQuiet(n)
	}
	if _, st := pairLoad(); st != 2 {
		id := "revoked"
		if c, st := pairLoad(); st == 0 {
			id = c.line.UUID
		}
		pairAudit("pair_reopened", id+" (pairing token rotated)")
		if err := os.Remove(pairStorePath()); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return PairingToken()
}

// PairingState says in words who this Kharej is paired with.
func PairingState() string {
	_, st := pairLoad()
	switch st {
	case 3:
		return "revoked: no Iran manages this server (rotate the token to pair again)"
	case 1:
		return "unreadable pairing store " + pairStorePath()
	case 0:
		if b, _ := os.ReadFile(pairStorePath()); strings.Contains(string(b), "\n# claimed") {
			return "paired with an Iran server"
		}
		return "paired by hand (watp1: line)"
	}
	return "waiting: the first Iran server that adds this token pairs with it"
}

// deleteQuiet removes a tunnel and its helpers without printing the delete's own lines.
func deleteQuiet(n string) {
	old := Stdout
	Stdout = io.Discard
	defer func() { Stdout = old }()
	deleteNow(n)
}

// pairTokenCmd is `wattun pair-token [--rotate]` and the dashboard's t on Kharej.
func pairTokenCmd(rotate bool) bool {
	if rotate {
		if !NonInteractive {
			Warn("The old token stops working. The Iran server paired now loses its link and has to add this Kharej again.")
			if !Confirm("Make a new pairing token?", false) {
				return false
			}
		}
		Hint("Making a new pairing token (a minute at most) ...")
		tok, err := RotatePairingToken()
		if err != nil {
			Err(err.Error())
			return false
		}
		return showPairingToken(tok)
	}
	if kharejLink() == "" {
		Hint("Making this server's pairing token (a minute at most) ...")
	}
	tok, err := PairingToken()
	if err != nil {
		Err(err.Error())
		return false
	}
	return showPairingToken(tok)
}

func showPairingToken(tok string) bool {
	if NonInteractive || !IsTTY {
		Say("TOKEN=" + tok)
		Say("PAIRING=" + PairingState())
		return true
	}
	sel := 0
	ClearScreen()
	for {
		state := PairingState()
		head := func(w io.Writer) {
			Title(w, "Pairing token", "add this Kharej on the Iran server")
			fmt.Fprintln(w)
			fmt.Fprintf(w, "%s%s%s\n\n", BOLD, tok, RST)
			fmt.Fprintln(w, KV(9, "pairing", state))
			fmt.Fprintln(w)
			hintLine(w, "On the Iran server: wattun, Kharej servers, Add Kharej (or the web panel: Kharej servers, Add Kharej),")
			hintLine(w, "then paste this token. It holds the link's secret key: send it only over a private chat.")
			hintLine(w, "Your tunnels are then made from Iran, on both servers at once.")
			fmt.Fprintln(w)
		}
		i, k := Choose(head, []Item{{Key: "r", Label: "Rotate", Desc: "a new token; the old one stops working"}},
			&sel, []string{"r", "rotate", "esc", "back"}, 0)
		if i == 0 {
			k = "r"
		}
		switch k {
		case "r":
			ClearScreen()
			Title(Stdout, "Rotate the pairing token", "")
			Warn("The old token stops working. The Iran server paired now loses its link and has to add this Kharej again.")
			if !Confirm("Make a new pairing token?", false) {
				continue
			}
			Hint("Making a new pairing token (a minute at most) ...")
			nt, err := RotatePairingToken()
			if err != nil {
				Err(err.Error())
				Pause()
				continue
			}
			tok = nt
			ClearScreen()
		case "eof", "esc", "q", "0":
			return true
		}
	}
}

// ---- Iran: add and remove a Kharej ----

// IranLinks are this server's links, one per Kharej.
func IranLinks() []string {
	var out []string
	for _, n := range Links() {
		if Role(n) == "Iran" {
			out = append(out, n)
		}
	}
	return out
}

// linkHost is the Kharej host a link reaches.
func linkHost(n string) string {
	if t, err := ReadToken(TokenOf(n)); err == nil {
		h, _ := SplitHP(strings.SplitN(t.Peer, ",", 2)[0])
		if h != "" {
			return h
		}
	}
	return scepterPeerHost(n)
}

// pairLabel names a pair in lists: a link by its Kharej address, an older paired tunnel by its own name.
func pairLabel(n string) string {
	if IsLink(n) {
		return "Kharej " + linkHost(n)
	}
	return n
}

// pairShort is pairLabel without the word: the Kharej address of a link, else the tunnel name.
func pairShort(n string) string {
	if IsLink(n) {
		return linkHost(n)
	}
	return n
}

// linkTo is the link to HOST ("" none).
func linkTo(host string) string {
	for _, n := range IranLinks() {
		if linkHost(n) == host {
			return n
		}
	}
	return ""
}

// AddKharej makes the link to the Kharej that printed TOK and waits for the pairing; test is the carrier test
// preset ("" = fast). A link that already reaches that host is replaced (its token was rotated).
func AddKharej(tok, test string) (string, error) {
	tok = strings.TrimSpace(tok)
	t, err := ReadToken(tok)
	if err != nil {
		return "", fmt.Errorf("that is not a WatTunnel token (it starts with wat1:)")
	}
	if !strings.HasPrefix(t.Pair, "pair") {
		return "", fmt.Errorf("this token cannot pair. Use the pairing token Kharej shows (wattun on Kharej, then t; wattun 3.6.1 or newer there)")
	}
	if serverSide() == "kharej" {
		return "", fmt.Errorf("this server is the Kharej side; add Kharej servers on the Iran server")
	}
	if test == "reverse" { // reverse needs Kharej to know this server's address, learned on a first direct contact
		return "", fmt.Errorf("a new Kharej needs a direct carrier first: use --test fast, normal or anti")
	}
	host, _ := SplitHP(strings.SplitN(t.Peer, ",", 2)[0])
	old := linkTo(host) // replaced only once the new link works: a failed add keeps it
	name := freeLinkName()
	lp, err := envRandOpenPort("tcp", nil)
	if err != nil {
		return "", fmt.Errorf("no free local port for the link")
	}
	if err := writeFile0600(filepath.Join(P.Conf, name+".link"), "iran\n"); err != nil { // hidden from the start
		return "", err
	}
	saved, savedNI := NonInteractive, NI
	NonInteractive = true
	NI = niOpts{Name: name, Map: strconv.Itoa(lp) + ":1", Bind: "127.0.0.1", Test: orStr(test, "fast"), Pick: "best"}
	ok := wizardIranWith(tok, name)
	NonInteractive, NI = saved, savedNI
	if !ok || !fileExists(filepath.Join(P.Conf, name+".yml")) {
		deleteQuiet(name)
		return "", fmt.Errorf("no carrier reached %s; check that Kharej is up and try again", host)
	}
	// the token as key file arms the pairing; the token file marks the tunnel paired (IsPaired)
	if atomicWrite(filepath.Join(P.Conf, name+".key"), []byte(tok+"\n"), 0o600) != nil ||
		atomicWrite(filepath.Join(P.Conf, name+".token"), []byte(tok+"\n"), 0o600) != nil {
		deleteQuiet(name)
		return "", fmt.Errorf("could not write the link's key")
	}
	if !IsReverse(name) && Cfg(name, "latch-port") == "" {
		_ = SetValue(name, "latch-port", "20443") // Kharej's real port is learned later (scepterLearnLatchPort)
	}
	_ = Systemctl("restart", Unit(name))
	if old != "" {
		deleteQuiet(old)
	}
	return name, waitPaired(name, 45*time.Second)
}

// waitPaired waits for the link's first management answer: that is the claim on first contact.
func waitPaired(n string, d time.Duration) error {
	var last error
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(3 * time.Second) {
		cl, err := scepterDial(n)
		if err == nil {
			if _, err = scepterFetchDoc(cl); err == nil {
				return nil
			}
		}
		last = err
		if last != nil && strings.Contains(last.Error(), "another Iran") {
			break
		}
	}
	if last == nil {
		last = fmt.Errorf("no answer")
	}
	return fmt.Errorf("the link is up but Kharej did not answer the pairing yet: %v", last)
}

func addKharejCmd() bool {
	tok := NI.Token
	if tok == "" {
		if NonInteractive {
			Err("add-kharej needs --token wat1:...")
			return false
		}
		Page("Add Kharej", "pair this Iran server with a Kharej server")
		Hint("On the Kharej server run wattun and press t: it shows the pairing token.")
		if !AskOK("Pairing token from Kharej (wat1:...)", "", vToken) {
			return false
		}
		tok = ReplyV
	}
	Hint("Testing which carriers reach Kharej and making the link (a few minutes at most) ...")
	name, err := AddKharej(tok, NI.Test)
	if name == "" {
		Err(err.Error())
		return false
	}
	host := linkHost(name)
	if err != nil {
		Warn(err.Error())
		Hint("It usually pairs within a minute; Kharej servers shows it when it does.")
	} else {
		Ok("Paired with Kharej " + host + ".")
		Hint("Make tunnels on both servers at once: New tunnel → On Kharej and here.")
	}
	if NonInteractive {
		Say("LINK=" + name)
		Say("KHAREJ=" + host)
	}
	return true
}

// RemoveKharej deletes the link to a Kharej (host or link name). The owner's tunnels to it keep running; they
// are no longer managed from here.
func RemoveKharej(which string) error {
	n := which
	if !IsLink(n) || Role(n) != "Iran" {
		n = linkTo(which)
	}
	if n == "" {
		return fmt.Errorf("no Kharej %s is added here", which)
	}
	deleteQuiet(n)
	return nil
}

func removeKharejCmd(which string) bool {
	if which == "" {
		Err("remove-kharej needs the Kharej address")
		return false
	}
	if !NonInteractive && !Confirm("Remove Kharej "+which+"? Its tunnels keep running but are no longer managed from here.", false) {
		return false
	}
	if err := RemoveKharej(which); err != nil {
		Err(err.Error())
		return false
	}
	Ok("Kharej " + which + " removed.")
	return true
}

// PairHost is the Kharej a paired tunnel reaches: a link's from its token (a reverse link's peer is this
// server), any other tunnel's from its peer.
func PairHost(n string) string {
	if IsLink(n) {
		return linkHost(n)
	}
	return scepterPeerHost(n)
}

// IsLinkTunnel is IsLink for the panel.
func IsLinkTunnel(n string) bool { return IsLink(n) }

// PairingTokenNow is the pairing token when it is made already ("" = not yet; PairingToken makes it).
func PairingTokenNow() string {
	if n := kharejLink(); n != "" {
		return TokenOf(n)
	}
	return ""
}
