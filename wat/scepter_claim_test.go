package wat

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// servePairs serves every scepter stream of the given server sessions from one state (one Kharej, many Iran).
func servePairs(state *ScepterState, srvs ...*Session) {
	for _, srv := range srvs {
		go func(srv *Session) {
			for {
				st, err := srv.Accept()
				if err != nil {
					return
				}
				if st.ID() != 0 {
					st.Reset()
					continue
				}
				go ServeScepter(st, state)
			}
		}(srv)
	}
}

// Handoff 4 R2: the in-band stream serves nothing before a hello that proves the CURRENT pairing key.
func TestScepterHelloNeedsProof(t *testing.T) {
	pair := testPairing(CapFull)
	cli, srv, _, _ := newPair(t, 0, 2*time.Millisecond, 20e6, Config{Pairing: pair})
	t.Cleanup(func() { cli.Close(); srv.Close() })
	state, err := NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.Stop)
	servePairs(state, srv)
	st, err := cli.OpenScepter()
	if err != nil {
		t.Fatal(err)
	}
	wrong := *pair
	wrong.Key[0] ^= 1
	reqs := []ScepterRequest{
		{ID: "p", V: scepterV, Cmd: "state.get"},                                                                                   // before any hello
		{ID: "h1", V: scepterV, Cmd: "scepter.hello", Args: map[string]any{}},                                                      // no proof
		{ID: "h2", V: scepterV, Cmd: "scepter.hello", Args: map[string]any{"proofs": []string{ScepterProof(&wrong, cli.cfg.SID)}}}, // wrong key
		{ID: "h3", V: scepterV, Cmd: "scepter.hello", Args: map[string]any{"proofs": []string{ScepterProof(pair, srv.cfg.SID+2)}}}, // another session's proof
		{ID: "h4", V: scepterV, Cmd: "scepter.hello", Args: map[string]any{"proofs": []string{"x", ScepterProof(pair, cli.cfg.SID)}}},
		{ID: "s", V: scepterV, Cmd: "state.get"},
	}
	want := []int{CodeDenied, CodeDenied, CodeDenied, CodeDenied, CodeOK, CodeOK}
	go func() {
		for _, r := range reqs {
			r.TS = time.Now().Unix()
			b, _ := json.Marshal(r)
			st.Write(append(b, '\n'))
		}
	}()
	rd := bufio.NewReader(st)
	for i, w := range want {
		done := make(chan ScepterResponse, 1)
		go func() {
			var resp ScepterResponse
			line, _ := rd.ReadBytes('\n')
			json.Unmarshal(line, &resp)
			done <- resp
		}()
		select {
		case resp := <-done:
			if resp.Code != w || resp.ID != reqs[i].ID {
				t.Fatalf("request %s: code %d id %q, want %d", reqs[i].ID, resp.Code, resp.ID, w)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("request %s: no answer", reqs[i].ID)
		}
	}
}

// Handoff 4 R2: the first proven hello over the token bootstrap claims it — a fresh credential, stored once,
// returned once; afterwards the token alone is refused and the claimed credential is what proves.
func TestScepterClaim(t *testing.T) {
	boot := testPairing(CapFull) // stands in for the token-derived credential
	state, err := NewScepterState(boot, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.Stop)
	var stored []*PairingConfig
	state.SetClaimer(func(p *PairingConfig) error { stored = append(stored, p); return nil })

	cliA, srvA, _, _ := newPair(t, 0, 2*time.Millisecond, 20e6, Config{Pairing: boot})
	cliB, srvB, _, _ := newPair(t, 0, 2*time.Millisecond, 20e6, Config{Pairing: boot})
	t.Cleanup(func() { cliA.Close(); srvA.Close(); cliB.Close(); srvB.Close() })
	servePairs(state, srvA, srvB)

	a, err := DialScepter(cliA)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := a.Hello["claim"].(string)
	if !strings.HasPrefix(line, "watp1:") || len(stored) != 1 || stored[0].Line() != line {
		t.Fatalf("claim: hello %v, stored %d", a.Hello, len(stored))
	}
	claimed, err := ParsePairingLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Key == boot.Key || claimed.Caps != boot.Caps || !state.Holds(claimed) {
		t.Fatal("the claim must mint a NEW key with the bootstrap's caps and make it current")
	}
	if u, _ := a.Hello["uuid"].(string); u != claimed.UUIDString() {
		t.Fatalf("hello reports uuid %q, want the claimed %s", u, claimed.UUIDString())
	}
	// the claiming stream stays proven
	if _, code := a.Call("state.get", nil); code != CodeOK {
		t.Fatalf("claimer's next command: code %d", code)
	}

	// a second Iran with only the token: refused, and no second claim
	if _, err := DialScepter(cliB); err == nil {
		t.Fatal("the token alone must not open the management plane after the claim")
	}
	if len(stored) != 1 {
		t.Fatalf("a refused hello must not claim again: %d stores", len(stored))
	}
	// the claimed credential proves (a new session: the refused one reset its stream)
	cliC, srvC, _, _ := newPair(t, 0, 2*time.Millisecond, 20e6, Config{Pairing: boot})
	t.Cleanup(func() { cliC.Close(); srvC.Close() })
	servePairs(state, srvC)
	c, err := DialScepter(cliC, claimed)
	if err != nil {
		t.Fatalf("the claimed credential must prove: %v", err)
	}
	if _, again := c.Hello["claim"]; again {
		t.Fatal("a claim is handed out once")
	}
}
