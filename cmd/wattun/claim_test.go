package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// Handoff 4 R3: a revoke tombstone keeps the unit unpaired even when the tunnel token would derive a pairing;
// a missing store still lets the token arm (that is how a new Iran pairs).
func TestRevokeTombstoneBeatsToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	tok := &tokenPair{field10: "pair=full", key: "0123456789abcdef0123456789abcdef"}
	if p, origin, err := scepterAttach("", path, tok, t.Logf); err != nil || p == nil || origin != scepterFromToken {
		t.Fatalf("no store: the token must arm (%v %v %v)", p, origin, err)
	}
	writePairingStore(t, path, "revoked 00112233-4455-6677-8899-aabbccddeeff 2026-11-24T00:00:00Z\n")
	if _, err := readPairingFile(path); !errors.Is(err, errPairingRevoked) {
		t.Fatalf("tombstone read: %v", err)
	}
	if p, _, err := scepterAttach("", path, tok, t.Logf); err != nil || p != nil {
		t.Fatalf("a tombstone must keep the unit unpaired despite the token: %v %v", p, err)
	}
}

// Handoff 4 R2: the server stores the claim as its .pairing; the client keeps a deduplicated claims file.
func TestClaimStores(t *testing.T) {
	dir := t.TempDir()
	np, err := wat.ParsePairingLine(testPairingLine("full"))
	if err != nil {
		t.Fatal(err)
	}
	srvPath := filepath.Join(dir, ".pairing")
	if err := storePairingClaim(srvPath, np); err != nil {
		t.Fatal(err)
	}
	got, err := readPairingFile(srvPath)
	if err != nil || *got != *np {
		t.Fatalf("server store round trip: %v %v", got, err)
	}
	if fi, _ := os.Stat(srvPath); fi != nil && fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("store mode %v", fi.Mode().Perm())
	}
	cp := claimsPath(filepath.Join(dir, "ir.yml"))
	other, _ := wat.ParsePairingLine(testPairingLine("manage"))
	other.UUID[0] ^= 0xff
	for _, l := range []string{np.Line(), other.Line(), np.Line()} {
		if err := addClaim(cp, l); err != nil {
			t.Fatal(err)
		}
	}
	cs := readClaims(cp)
	if len(cs) != 2 {
		t.Fatalf("claims must dedupe by uuid: %d", len(cs))
	}
	if addClaim(cp, "garbage") == nil {
		t.Fatal("a non-watp1 claim must be refused")
	}
	if claimsPath("") != "" || readClaims("") != nil {
		t.Fatal("no config dir: no claims store")
	}
}

// Handoff 4 R2: in derived mode the claim's own write is not a rotation, and deleting the store re-opens the
// claim (the console's "allow a new Iran to pair") instead of disarming for good.
func TestPairingPollerReclaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pairing")
	dp, err := wat.ParsePairingTokenField("pair=full", []byte("kk"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := wat.NewScepterState(dp, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Stop)
	reclaims := 0
	var logs []string
	pl := &pairingPoller{path: path, scepter: st, derived: dp, reclaim: func() { reclaims++ },
		logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }, interval: time.Hour}
	startPairingPoller(pl)

	// the claim: the state switched in-process, then the store landed on disk
	np, _ := wat.ParsePairingLine(testPairingLine("full"))
	st.ReloadPairing(np)
	if err := storePairingClaim(path, np); err != nil {
		t.Fatal(err)
	}
	logs = nil
	pl.check()
	if len(logs) != 0 || !st.Holds(np) {
		t.Fatalf("the process's own claim write must be silent: %v", logs)
	}

	// delete the store: the token bootstrap is current and claimable again
	os.Remove(path)
	pl.check()
	if !st.Holds(dp) || reclaims != 1 {
		t.Fatalf("deleting the store must fall back to the token and re-arm the claim (reclaims %d)", reclaims)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "claimable again") {
		t.Fatalf("reclaim log: %v", logs)
	}

	// a tombstone: disarmed
	writePairingStore(t, path, "revoked x\n")
	fut := time.Now().Add(2 * time.Second)
	os.Chtimes(path, fut, fut)
	pl.check()
	if u, _ := st.PairingInfo(); u != "" {
		t.Fatalf("a tombstone must disarm: %s", u)
	}
}
