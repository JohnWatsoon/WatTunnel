// Scepter, the pairing and management plane (3.5.0, phase A — the read-only cockpit).
//
// A pairing credential turns a tunnel's session into a management channel: the client (Iran, the cockpit) opens
// the reserved stream sid 0 (session.go OpenScepter) and speaks JSON Lines with the server (Kharej), inside the
// session's AEAD — nothing is plaintext on the wire. No new frame type exists; an unpaired or old peer simply
// never sees sid 0. Both ends need 3.5.0 for any Scepter feature (docs/TECHNICAL.md version matrix).
//
// Wire format (plan D7): one JSON object per line.
//
//	request  {"id":"…","v":1,"cmd":"…","args":{…},"ts":1732267200,"ttl":600}
//	response {"id":"…","code":0,"params":{…},"seq":123}
//
// Codes are machine integers, never prose (the future panel localizes them). Large payloads (log fetches) are
// chunked: consecutive responses with the same id and params {"chunk":i,"of":n,"data":"…"}; the client
// concatenates data in order. Every command line is capped at 64 KiB; anything bigger or malformed is
// code=bad_request and never a crash (validated like parseRepairAsk in repair.go).
package wat

import (
	"bufio"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNoPairing = errors.New("wat: session is not paired")

// Capability tiers (plan D4). Each tier is one bit, and a credential's mask is CUMULATIVE (CapFromName issues
// every lower tier's bit with the granted one), so the server-side check on each command is a single AND —
// "tunnel < create < manage < full" never needs ordering logic at the check site.
const (
	CapTunnel uint32 = 1 << iota // today's token, unchanged: run tunnels, read the pairing's own state
	CapCreate                    // + create tunnels (phase B)
	CapManage                    // + edit/delete/test/stats/logs/events (phase A read commands live here)
	CapFull                      // + update orchestration (phase D)
)

// CapName returns the highest tier name a mask grants ("" for an empty mask).
func CapName(caps uint32) string {
	switch {
	case caps&CapFull != 0:
		return "full"
	case caps&CapManage != 0:
		return "manage"
	case caps&CapCreate != 0:
		return "create"
	case caps&CapTunnel != 0:
		return "tunnel"
	}
	return ""
}

// CapFromName parses one tier name (plan D5's capability field is a word, not a bitmask string) into the
// cumulative mask for that tier: a credential granted at a tier carries every lower tier's bit too.
func CapFromName(s string) (uint32, bool) {
	switch s {
	case "tunnel":
		return CapTunnel, true
	case "create":
		return CapTunnel | CapCreate, true
	case "manage":
		return CapTunnel | CapCreate | CapManage, true
	case "full":
		return CapTunnel | CapCreate | CapManage | CapFull, true
	}
	return 0, false
}

// PairingConfig is the pairing credential (plan D4): identity (UUID), a 32-byte key, a capability mask and a
// credential version. The key is what future phases (the fallback latch, rotation) derive shared secrets from;
// phase A's hello does not carry a keyed proof because the channel already sits inside the session AEAD and both
// pairing files are root-only local state — the latch (phase A item 4, not this commit) is where a proof pays off.
type PairingConfig struct {
	UUID [16]byte
	Key  [32]byte
	Caps uint32
	Ver  int
}

// ParsePairingLine parses the watp1: bootstrap line (plan D5):
//
//	watp1:<version>|<pairing UUID>|<base64 32-byte key>|<capability>
//
// Only version 1 exists. install.sh prints this line next to the first token; -pair on Kharej stores it verbatim.
func ParsePairingLine(s string) (*PairingConfig, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "watp1:") {
		return nil, fmt.Errorf("pairing line must start with watp1:")
	}
	f := strings.Split(strings.TrimPrefix(s, "watp1:"), "|")
	if len(f) != 4 {
		return nil, fmt.Errorf("pairing line wants 4 fields (version|uuid|key|capabilities), got %d", len(f))
	}
	var ver int
	if _, err := fmt.Sscanf(f[0], "%d", &ver); err != nil || ver != 1 {
		return nil, fmt.Errorf("pairing line version must be 1, got %q", f[0])
	}
	var p PairingConfig
	if err := uuidParse(f[1], &p.UUID); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("pairing key must be base64 of 32 bytes")
	}
	copy(p.Key[:], key)
	caps, ok := CapFromName(f[3])
	if !ok {
		return nil, fmt.Errorf("pairing capabilities must be tunnel|create|manage|full, got %q", f[3])
	}
	p.Caps, p.Ver = caps, ver
	return &p, nil
}

// ParsePairingTokenField parses optional field 10 of a classic wat1: token (plan D5): "pair" or "pair=<capability>"
// marks the token's key as also a pairing credential. The UUID is derived from the key (sha256 prefix) because a
// classic token carries none. Fields 1-9 are the manager's business; an old 6/7/9-field token has no field 10 and
// parses to (nil, nil) — the token-format rule (optional trailing fields) is preserved. Anything else starting
// with "pair" ("pairxyz", "pairing") is NOT the pair field and parses to (nil, nil) too: only the exact shapes
// above mark a credential (L5-strict, 2026-11-22 — a prefix match once silently promoted "pairxyz" to a
// tunnel-capability pairing).
func ParsePairingTokenField(field10 string, tokenKey []byte) (*PairingConfig, error) {
	if field10 == "" || !strings.HasPrefix(field10, "pair") {
		return nil, nil
	}
	if tier := field10[len("pair"):]; tier != "" && tier[0] != '=' {
		return nil, nil // a lookalike field (a future pair* extension): not a pairing credential
	}
	caps := CapTunnel
	if _, rest, ok := strings.Cut(field10, "="); ok {
		c, valid := CapFromName(rest)
		if !valid {
			return nil, fmt.Errorf("token pair field wants pair[=tunnel|create|manage|full], got %q", field10)
		}
		caps = c
	}
	if len(tokenKey) == 0 {
		return nil, fmt.Errorf("token pair field needs the token key")
	}
	var p PairingConfig
	p.Ver = 1
	p.Caps = caps
	// UUID = first 16 bytes of sha256("wat-pairing:" + key): stable per key, no new entropy to distribute.
	h := sha256.Sum256(append([]byte("wat-pairing:"), tokenKey...))
	copy(p.UUID[:], h[:16])
	if len(tokenKey) == 32 {
		copy(p.Key[:], tokenKey)
	} else {
		copy(p.Key[:], h[32:]) // a short token key is stretched to the 32-byte pairing key
	}
	return &p, nil
}

// Line renders the canonical watp1: line (what -pair accepted and stored).
func (p *PairingConfig) Line() string {
	return fmt.Sprintf("watp1:%d|%s|%s|%s", p.Ver, uuidStr(&p.UUID), base64.StdEncoding.EncodeToString(p.Key[:]), CapName(p.Caps))
}

// UUIDString formats the pairing UUID in canonical form.
func (p *PairingConfig) UUIDString() string { return uuidStr(&p.UUID) }

func uuidStr(u *[16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func uuidParse(s string, u *[16]byte) error {
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 {
		return fmt.Errorf("pairing UUID must be 32 hex chars, got %q", s)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("pairing UUID: %v", err)
	}
	copy(u[:], b)
	return nil
}

// ---- JSONL codec (plan D7) ----

// Response codes: machine integers, never prose. The panel localizes later; new codes append only.
const (
	CodeOK          = 0
	CodeBadRequest  = 1 // malformed line, wrong version, bad args
	CodeDenied      = 2 // capability insufficient
	CodeStale       = 3 // intent TTL expired
	CodeRateLimited = 4 // per-pair command rate exceeded
	CodeUnknownCmd  = 5
	CodeNotFound    = 6 // no such tunnel / event range
	CodeInternal    = 7
	CodeTooLarge    = 8 // command line above scepterMaxLine
	CodeUnpaired    = 9 // peer spoke scepter without a pairing (or the answer said so)
	// Phase B write-intent rejections (plan B.2), appended in order:
	CodeNameTaken    = 10 // tunnel.create: the name already exists on Kharej; params {"name"}
	CodePortBusy     = 11 // a listen port collides with another tunnel or a local listener; params {"port","user"}
	CodeCarrierNeeds = 12 // the carrier cannot run on this Kharej; params {"carrier","ver","need"}
)

const (
	scepterMaxLine = 64 << 10    // per-command size cap (plan: 64 KB/command)
	scepterChunk   = 16 << 10    // payload bytes per chunked response line (logs)
	scepterV       = 1           // protocol version of this engine
	scepterTTL     = 600         // default intent TTL, seconds (plan: 600)
	scepterSkew    = time.Minute // tolerated client/server clock error for the TTL check
	scepterEvents  = 512         // event ring size (plan: last 512 events replayable)

	// Event coalescing (plan E.1): a flapping tunnel must not flood the ring or the channel — at most one
	// event per scepterEvWindow per (type, subject) reaches the ring; repeats are dropped, never queued,
	// while state_seq still advances. scepterEvKeys caps the subject table (probes mint new ids forever);
	// when the cap is hit, entries older than the window are pruned — always safe, an expired entry could
	// never coalesce anything (the next event for that key fires and refreshes it).
	scepterEvWindow = time.Second
	scepterEvKeys   = 4096
)

// ScepterRequest is one command line. TS is the client's unix-seconds timestamp; TTL the intent's lifetime
// (0 = the 600 s default). Retries reuse the same ID (at-most-once application via the journal).
type ScepterRequest struct {
	ID   string         `json:"id"`
	V    int            `json:"v"`
	Cmd  string         `json:"cmd"`
	Args map[string]any `json:"args,omitempty"`
	TS   int64          `json:"ts,omitempty"`
	TTL  int            `json:"ttl,omitempty"`
}

// ScepterResponse is one answer line. Seq is the server's state_seq at answer time (the "response tail" of the
// plan's state model: clients diff by seq, never by wall clock). Chunk is non-nil for chunked payloads.
type ScepterResponse struct {
	ID     string         `json:"id"`
	Code   int            `json:"code"`
	Params map[string]any `json:"params,omitempty"`
	Seq    uint64         `json:"seq"`
	Chunk  *ScepterChunk  `json:"chunk,omitempty"`
}

// ScepterChunk marks response i of n carrying one piece of a large payload.
type ScepterChunk struct {
	I    int    `json:"chunk"`
	N    int    `json:"of"`
	Data string `json:"data"`
}

// scepterDecoder reads request lines with the size cap. A line longer than scepterMaxLine is drained and rejected
// with CodeTooLarge instead of buffering without bound — the authenticated peer may still send garbage (the plan's
// parser-robustness requirement; same discipline as parseRepairAsk in repair.go).
type scepterDecoder struct {
	br *bufio.Reader
}

func newScepterDecoder(r io.Reader) *scepterDecoder {
	// One line must fit the buffer whole (ReadSlice stops at the first '\n' only inside the buffer): commands
	// are legal up to scepterMaxLine CONTENT bytes — the cap excludes the line terminator, round-2 fix 5,
	// 2026-11-22, which also covers the \r\n shape — and a chunked response line is ~scepterChunk + overhead,
	// so both fit with room. A line that fills the buffer WITHOUT a newline is by construction over the cap:
	// drained, rejected.
	return &scepterDecoder{br: bufio.NewReaderSize(r, scepterMaxLine+64)}
}

func (d *scepterDecoder) next() (ScepterRequest, int) {
	line, err := d.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		for {
			b, e := d.br.ReadSlice('\n')
			if e != bufio.ErrBufferFull {
				break
			}
			_ = b
		}
		return ScepterRequest{}, CodeTooLarge
	}
	if err != nil {
		if len(line) == 0 {
			// no data with the error: the stream is dead (session closed/reset — Stream.Read then answers the
			// same error forever), so the loop must END. Returning bad_request here spun the serve loop hot on
			// marshal+read-error forever, one burned core per closed scepter pair (found by the phase B suite:
			// every closed pair left a runnable goroutine in writeRespLine). Data WITH the error is the other
			// case: a final unterminated garbage line, answered once, then the clean EOF below ends the loop.
			return ScepterRequest{}, -1
		}
		return ScepterRequest{}, CodeBadRequest
	}
	if len(trimEOL(line)) > scepterMaxLine { // the cap counts content bytes, terminator excluded (round-2 fix 5)
		return ScepterRequest{}, CodeTooLarge
	}
	var req ScepterRequest
	if err := json.Unmarshal(trimEOL(line), &req); err != nil {
		return ScepterRequest{}, CodeBadRequest
	}
	if req.V != scepterV {
		return req, CodeBadRequest // partial: id/cmd parsed — the audit names the attempt (L4, 2026-11-22)
	}
	return req, CodeOK
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// ---- events, state document, journal, rate limit ----

// Scepter event types (plan's state model; every change bumps state_seq).
const (
	EvTunnelUp        = "tunnel_up"
	EvTunnelDown      = "tunnel_down"
	EvTunnelDeleted   = "tunnel_deleted"
	EvCarrierSwitched = "carrier_switched"
	EvTunnelEdited    = "tunnel_edited" // phase B: edit/limits.set/preset.apply applied (not in the plan's phase-A list; appended, data not commands)
	EvHealAction      = "heal_action"
	EvSLABreach       = "sla_breach"
	EvUpdateAvailable = "update_available"
	EvPairRotated     = "pair_rotated"
	EvPairRevoked     = "pair_revoked"
	EvScepterUp       = "scepter_up"
	EvScepterDown     = "scepter_down"
	// Phase C (remote carrier work), appended like EvTunnelEdited: data, not commands.
	EvTestOpened = "test_opened" // a remote probe listener came up (test.open / the auto-test core)
	EvTestClosed = "test_closed" // a probe listener closed (ttl expiry or test.close)
	EvAutoTested = "auto_test"   // a fleet auto-test run finished (detail: mode, ok, total)
	// Phase D (operations). update_started is fired by the update.run handler itself; applied/failed are
	// fired by the status watcher (watchUpdateStatus) — the update job restarts the very engine that would
	// have to fire them, so the events travel across the restart in the .update.status file (the journal
	// replay of the original update.run intent covers the channel side; see docs/TECHNICAL.md).
	EvUpdateStarted = "update_started"
	EvUpdateApplied = "update_applied"
	EvUpdateFailed  = "update_failed"
)

// Phases of ScepterUpdateStatus, the cross-restart update mailbox ($CONF/.update.status). The engine writes
// started when update.run accepts an intent and stages a release; the update job (the binary re-exec'd as
// `wattun -update-job`, a transient systemd unit that outlives the engine restart) writes the terminal phase.
// The watcher turns each phase the engine observes into an event; update.status serves the raw record.
const (
	UpdatePhaseStarted    = "started"     // intent accepted, staging/launch in progress (the engine writes it)
	UpdatePhaseApplied    = "applied"     // new binary installed and every recorded unit stayed up
	UpdatePhaseFailed     = "failed"      // download/verify/install failed, or the rollback itself failed
	UpdatePhaseRolledBack = "rolled_back" // new engine did not stay up; wattun.prev restored and restarted
)

// ScepterUpdateStatus is one record of the update mailbox. Written by the engine (UpdatePhaseStarted) and
// the update job (terminal phases), read by the watcher and by update.status. Atomic tmp+rename every write.
type ScepterUpdateStatus struct {
	Phase  string `json:"phase"`
	Run    string `json:"run,omitempty"` // the update.run command id that started it
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"` // the resolved target version ("" while still latest-resolving)
	Detail string `json:"detail,omitempty"`
	Ts     int64  `json:"ts"`
}

// ScepterUpdateStatusFile is the mailbox file name, relative to the config dir (next to .pairing and the
// journal). The engine writes and reads it; defined here because the watcher (this package) and the ops
// (cmd/wattun) must never drift apart on the path.
const ScepterUpdateStatusFile = ".update.status"

// ScepterEvent is one numbered event; Seq is its state_seq.
type ScepterEvent struct {
	Seq    uint64         `json:"seq"`
	Type   string         `json:"type"`
	TS     int64          `json:"ts"`
	Detail map[string]any `json:"detail,omitempty"`
}

// ScepterTunnelInfo is one entry of the state document's tunnel list.
type ScepterTunnelInfo struct {
	Name    string `json:"name"`
	Carrier string `json:"carrier"`
	Ports   string `json:"ports,omitempty"`
	State   string `json:"state"`             // "active" | "inactive"
	Health  string `json:"health"`            // "ok" | "down"
	Metrics string `json:"metrics,omitempty"` // 127.0.0.1:port of this unit's /stats
}

// ScepterSource is the live view the state document is built from (implemented by the binary over its own unit;
// a multi-tunnel Kharej aggregates across units in a later phase). Kharej owns state: these reads never mutate.
type ScepterSource interface {
	Tunnels() []ScepterTunnelInfo
	TunnelStats(name string) (map[string]any, bool)
	TunnelLogs(name string, tail int) ([]string, bool)
	History(name string) ([]map[string]any, bool)
}

// scepterMutations is the set of MUTATING commands — the only ones the journal records (H1/F4, 2026-11-22).
// At-most-once application (the journal's reason to exist) only means anything for commands that change
// Kharej; every read (hello, ping, state.get, tunnels.list, tunnel.stats, tunnel.logs, events.since,
// history, auto.rows, doctor.fetch, audit.tail, update.status, backup.export) is a re-executable pure
// function of Kharej's live state, and journaling it once grew j.keep without bound (big log fetches) and
// made a journaled hello from a previous engine life replay verbatim across an update. Writes NOT in this
// set on purpose: auto.test triggers a run but answers before it (a repeat answers already_running, nothing
// double-applies), so a replayed outcome would only freeze an old run id in place.
var scepterMutations = map[string]bool{
	"tunnel.create":  true,
	"tunnel.edit":    true,
	"tunnel.delete":  true,
	"tunnel.start":   true,
	"tunnel.stop":    true,
	"tunnel.restart": true,
	"limits.set":     true,
	"preset.apply":   true,
	"carrier.change": true,
	"auto.apply":     true,
	"test.open":      true,
	"test.close":     true,
	"update.run":     true,

	// U0 audit coverage (2026-11-23): a PSK rotation rewrites the tunnel files, a credential rotation
	// rewrites the .pairing store, a mute flips a bonded path's manual state — all change Kharej, so all
	// replay at-most-once. limits.reset is deliberately NOT here: a quota reset is idempotent bookkeeping
	// (re-running it clears the same counters), and a replayed reset would pin stale quota state —
	// re-execution is the recovery, like the reads and the failed writes.
	"tunnel.keyrotate": true,
	"pair.rotate":      true,
	"carrier.mute":     true,
}

// scepterJournalKeep bounds the in-memory replay set (H1/F4, 2026-11-22): insertion-ordered ids, the oldest
// pruned past 4096. Retries arrive within minutes; 4096 mutations is months of cockpit traffic, and a
// pruned id simply re-executes (reads re-execute anyway; a re-executed write re-validates against Kharej's
// reality, so the worst case is a structured rejection like name_taken, never a broken state).
const (
	scepterJournalRotate = 1 << 20
	scepterJournalKeep   = 4096
)

// ScepterJournal is the append-only command journal (plan: every MUTATING intent with client id, outcome,
// state_seq; rotated at 1 MB; retries of the same command id return the recorded outcome). Records are
// appended with a single O_APPEND write (POSIX-atomic at the sizes involved, ~1 KB) and rotation writes a
// fresh tmp file that atomically replaces the live one — the same discipline as the manager's state files.
type ScepterJournal struct {
	mu    sync.Mutex
	path  string
	f     *os.File
	size  int64
	keep  map[string]journalRec // in-memory replay of live ids, bounded at scepterJournalKeep
	order []string              // keep's keys in insertion order: pruning drops order[0] first
}

// journalRec is the on-disk line.
type journalRec struct {
	ID   string          `json:"id"`
	Cmd  string          `json:"cmd"`
	TS   int64           `json:"ts"`
	Resp ScepterResponse `json:"resp"`
}

// OpenScepterJournal loads existing ids (for idempotent retries across a restart) and positions for append.
// A nil path means "no journal" (tests, or pairing without persistence): retries then re-execute. The load
// keeps only the newest scepterJournalKeep records — a journal written by an older engine may hold more
// (it once journaled reads too); lines are chronological, so the tail is the live set.
func OpenScepterJournal(path string) (*ScepterJournal, error) {
	j := &ScepterJournal{path: path, keep: map[string]journalRec{}}
	if path == "" {
		return j, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		var recs []journalRec
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var r journalRec
			if json.Unmarshal([]byte(line), &r) == nil && r.ID != "" {
				recs = append(recs, r)
			}
		}
		if len(recs) > scepterJournalKeep {
			recs = recs[len(recs)-scepterJournalKeep:]
		}
		for _, r := range recs {
			if _, dup := j.keep[r.ID]; !dup {
				j.order = append(j.order, r.ID)
			}
			j.keep[r.ID] = r
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil {
		j.size = st.Size()
	}
	j.f = f
	return j, nil
}

// Record appends one outcome and remembers it for idempotent retries, pruning the oldest id past the bound.
func (j *ScepterJournal) Record(cmd, id string, ts int64, resp ScepterResponse) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if id == "" {
		return // an id-less line (should not happen) is not replayable anyway
	}
	rec := journalRec{ID: id, Cmd: cmd, TS: ts, Resp: resp}
	if j.f != nil {
		b, err := json.Marshal(rec)
		if err == nil {
			b = append(b, '\n')
			if n, werr := j.f.Write(b); werr == nil {
				j.size += int64(n)
			}
		}
		if j.size >= scepterJournalRotate {
			j.rotateLocked()
		}
	}
	if _, dup := j.keep[id]; !dup { // a re-recorded id (same id, different cmd) keeps its original place
		j.order = append(j.order, id)
	}
	j.keep[id] = rec
	for len(j.order) > scepterJournalKeep {
		delete(j.keep, j.order[0])
		j.order = j.order[1:]
	}
}

func (j *ScepterJournal) rotateLocked() {
	j.f.Close()
	tmp := j.path + ".tmp"
	var b strings.Builder
	for _, id := range j.order { // the pruned live set only, in insertion order; old ids age out
		if r, ok := j.keep[id]; ok {
			if line, err := json.Marshal(r); err == nil {
				b.Write(line)
				b.WriteByte('\n')
			}
		}
	}
	if err := os.WriteFile(tmp, []byte(b.String()), 0600); err == nil {
		os.Rename(tmp, j.path) // atomic replace, manager-file discipline
	}
	if f, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		j.f, j.size = f, 0
	} else {
		j.f, j.size = nil, 0
	}
}

// Close releases the journal file (Windows keeps the directory locked while it is open, which otherwise
// breaks a test's TempDir cleanup; harmless no-op without a file).
func (j *ScepterJournal) Close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f != nil {
		j.f.Close()
		j.f = nil
	}
}

// Lookup returns the recorded outcome for a command id, if any. The recorded COMMAND must match too
// (F4/M2, 2026-11-22): a client reusing an id for a different command misses here — and Handle answers the
// reuse bad_request via Conflict below WITHOUT re-recording (round-2 fix 1, 2026-11-22), so the stored
// outcome stays for the original command's retry. A record with an empty Cmd is a rotation artifact of the
// pre-fix writer (rotateLocked once dropped the field); it matches any command, which is the safe side:
// replaying a recorded mutating outcome beats re-running the op blind.
func (j *ScepterJournal) Lookup(id, cmd string) (ScepterResponse, bool) {
	if j == nil || id == "" {
		return ScepterResponse{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.keep[id]
	if !ok || (r.Cmd != "" && r.Cmd != cmd) {
		return ScepterResponse{}, false
	}
	return r.Resp, true
}

// Conflict reports whether the id is already recorded for a DIFFERENT command (round-2 fix 1, 2026-11-22).
// Handle answers such a reuse bad_request and stops: re-recording over the id would erase the original
// command's outcome, and its legit retry would then miss here and re-execute a mutation (double-apply). A
// record with an empty Cmd (the pre-fix writer's artifact, see Lookup) is not a conflict — it matches any
// command.
func (j *ScepterJournal) Conflict(id, cmd string) bool {
	if j == nil || id == "" {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.keep[id]
	return ok && r.Cmd != "" && r.Cmd != cmd
}

// ---- command audit (plan E.3): every command, every outcome, with the credential UUID ----

// ScepterAuditFile is the shared credential+command audit file, relative to the config dir: wattun-manager's
// console appends its pairing events (pair_created/pair_rotated/pair_revoked) here, the engine appends one
// line per handled command (ScepterAudit below), and audit.tail (cmd/wattun/scepter_ops.go, the `audit`
// source) returns the tail raw. Defined here so the three sides cannot drift on the path or the format.
const ScepterAuditFile = ".pairing.audit"

// scepterAuditEvent is the <event> token of an engine-written audit line; the manager uses pair_* tokens.
// The shared line shape is "<RFC3339 UTC> <event> <detail>" (documented in docs/TECHNICAL.md, audit.tail).
const scepterAuditEvent = "scepter_cmd"

// ScepterAudit is the append-only command audit (plan E.3): every handled command — every outcome, not just
// the journaled ones — lands as one line
//
//	<RFC3339 UTC> scepter_cmd uuid=<pairing UUID> cmd=<cmd> code=<code> id=<id>
//
// in ScepterAuditFile, the SAME file and line shape the manager's pairing_audit writes, so audit.tail (and
// the manager's audit view) read ONE credential+command trail and "who tried what" covers denied/stale/
// rate_limited/unknown commands too. The journal above stays outcomes-only (applied intents and rolled-back
// writes) for at-most-once replay; the audit is evidence. Rotation reuses the journal's threshold
// (scepterJournalRotate) but preserves the old generation: the live file is RENAMED to ScepterAuditFile+".1"
// (the journal's rotate instead keeps only live ids in place — the audit's old content is evidence, it moves
// aside and is never rewritten away; one generation, so the file set stays bounded). audit.tail reads the
// live file only.
//
// Writer shape, deliberately different from the journal's held fd: one open-append-close per record. The
// manager REWRITES this file (read-modify-write + rename) on each console append, which re-points the path —
// a held fd would keep appending to the replaced inode and silently lose audit lines. Per-record opens
// always follow the live file; the cost is three syscalls per command, bounded by the per-pair rate bucket
// (20 commands/s). Lines never interleave mid-line: every write and the rotation decision hold one mutex.
type ScepterAudit struct {
	mu   sync.Mutex
	path string
	size int64 // last known size, refreshed from the file itself (the manager's rewrites resize it too)
}

// OpenScepterAudit probes the audit file (creating it) and returns the writer.
func OpenScepterAudit(path string) (*ScepterAudit, error) {
	a := &ScepterAudit{path: path}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil {
		a.size = st.Size()
	}
	f.Close()
	return a, nil
}

// record appends one line. Write errors are best effort (the tunnel keeps serving when the disk fills; the
// journal's semantics differ because replayed outcomes, not evidence, ride on it).
func (a *ScepterAudit) record(now time.Time, uuid, cmd, id string, code int) {
	if a == nil || a.path == "" {
		return
	}
	line := fmt.Sprintf("%s %s uuid=%s cmd=%s code=%d id=%s\n", now.UTC().Format(time.RFC3339),
		scepterAuditEvent, uuid, scepterAuditToken(cmd), code, scepterAuditToken(id))
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	_, werr := f.Write([]byte(line))
	f.Close()
	if st, serr := os.Stat(a.path); serr == nil {
		a.size = st.Size() // the truth, wherever the manager's console rewrites left it
	} else if werr == nil {
		a.size += int64(len(line))
	}
	if a.size >= scepterJournalRotate {
		if err := os.Rename(a.path, a.path+".1"); err != nil {
			// one generation preserved (type comment); the next record starts fresh. A plain rename onto an
			// existing file FAILS on Windows and the error was once ignored — the live audit then grew
			// without bound on a dev checkout (round-2 fix 7, 2026-11-22): drop the stale generation and
			// retry once; evidence rotates, it is not lost.
			os.Remove(a.path + ".1")
			os.Rename(a.path, a.path+".1")
		}
		a.size = 0
	}
}

// scepterAuditToken keeps one audit line ONE line: cmd and id come from the peer (authenticated, but an
// embedded newline would forge audit entries), so anything outside printable ASCII collapses to '_' and the
// token is capped at 64 bytes.
func scepterAuditToken(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r >= 0x20 && r < 0x7f {
			return r
		}
		return '_'
	}, s)
}

// scepterRate is the per-pair token bucket on commands (plan: commands/s). Generous for a human cockpit, tight
// for a runaway loop; a journaled retry still costs a token so replay-spam is bounded too.
type scepterRate struct {
	rate, burst, tokens float64
	at                  time.Time
}

func (r *scepterRate) allow(now time.Time) bool {
	if r.at.IsZero() {
		r.at, r.tokens = now, r.burst
	}
	r.tokens = min(r.tokens+now.Sub(r.at).Seconds()*r.rate, r.burst)
	r.at = now
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// ScepterState is one pairing's server-side management state: the state document, the event ring, the journal
// and the rate buckets. One per pairing credential per process; safe for concurrent streams.
type ScepterState struct {
	mu      sync.Mutex
	pair    *PairingConfig
	started time.Time
	seq     uint64
	events  []ScepterEvent // ring: capped at scepterEvents, oldest dropped
	evFire  map[string]time.Time
	// evWindow is the coalescing window (scepterEvWindow); a field so tests can disable coalescing (0) to
	// drill the raw ring behaviour — the same seam pattern as nowf.
	evWindow time.Duration
	src      ScepterSource
	ops      ScepterOps // the write side (phase B); nil until SetOps — then write commands answer unknown_cmd
	journal  *ScepterJournal
	audit    *ScepterAudit // the shared command audit (plan E.3); nil without a persistent journal dir
	rate     scepterRate
	// createRate is the slower per-pair "structural" bucket on the unit-restarting ops — tunnel.create (plan
	// B.2: "creation/test rate limits per pair"), carrier.change and auto.apply (phase C): five at once, then
	// one per 10 s — a human cockpit never feels it, a runaway loop stops.
	createRate scepterRate
	// probeRate bounds test.open (phase C: "rate-limited per pair like other write commands"): three probe
	// listeners at once, then one per 30 s. The auto-test core's own probes bypass this bucket (the run is
	// already gated by autoRate below); autoRate bounds auto.test itself.
	probeRate scepterRate
	autoRate  scepterRate
	// updateRate bounds update.run (phase D): one at once, then one per 5 min — an update is the most
	// structural op the cockpit can ask for, and a retry loop must never machine-gun restarts of the host.
	updateRate scepterRate
	// rotateRate bounds pair.rotate (U0 audit, 2026-11-23): update-rate-like, one per 5 min — a credential
	// may rotate itself, but a rotation loop would churn the .pairing store and strand every OTHER cockpit
	// that still holds the previous line.
	rotateRate  scepterRate
	updateWatch atomic.Bool // the status watcher is spawned once per state (SetOps)
	// watchStop/watchDone shut the tunnel liveness watcher down (Stop); watchSnap is its last per-tunnel
	// snapshot: the last-observed direction, the direction the SCEPTER path last announced (watchAnnounced,
	// the double-fire suppression) and the consecutive-miss count of an absent tunnel (the two-miss rule).
	// lives holds the scepter streams this state is currently serving so a disarm (ReloadPairing(nil)) can
	// kill them mid-line.
	watchStop chan struct{}
	watchDone chan struct{}
	watchSnap map[string]scepterWatchEnt
	lives     map[*Stream]struct{}
	qmu       sync.Mutex       // the ONE command queue (plan B.4/E.2): held from idempotency replay to journal record
	recent    []ScepterRec     // last scepterRecent handled commands: the doctor's ONLY visible trace (plan A.3)
	nowf      func() time.Time // tests shrink the clock
}

// ScepterRec is one handled command for the doctor's "last commands" line (Recent).
type ScepterRec struct {
	Cmd  string `json:"cmd"`
	Code int    `json:"code"`
	TS   int64  `json:"ts"`
}

const scepterRecent = 16

// NewScepterState builds the state for a pairing. journalPath may be empty (no journal). src may be nil (the
// tunnel-listing commands answer empty until the binary wires a source). When journalPath is set, the shared
// command audit (ScepterAuditFile) is opened next to it — the same config dir the manager's console writes and
// audit.tail reads — and a failing audit is fatal, like a failing journal: an audit that silently never
// writes is exactly the gap plan E.3 closes.
func NewScepterState(pair *PairingConfig, src ScepterSource, journalPath string) (*ScepterState, error) {
	j, err := OpenScepterJournal(journalPath)
	if err != nil {
		return nil, err
	}
	ss := &ScepterState{
		pair: pair, src: src, journal: j, started: time.Now(),
		rate:       scepterRate{rate: 20, burst: 40},
		createRate: scepterRate{rate: 0.1, burst: 5},
		probeRate:  scepterRate{rate: 1.0 / 30, burst: 3},
		autoRate:   scepterRate{rate: 1.0 / 60, burst: 2},
		updateRate: scepterRate{rate: 1.0 / 300, burst: 1},
		rotateRate: scepterRate{rate: 1.0 / 300, burst: 1},
		evFire:     map[string]time.Time{},
		evWindow:   scepterEvWindow,
		nowf:       time.Now,
	}
	if journalPath != "" {
		a, err := OpenScepterAudit(filepath.Join(filepath.Dir(journalPath), ScepterAuditFile))
		if err != nil {
			j.Close()
			return nil, err
		}
		ss.audit = a
	}
	if src != nil { // the tunnel liveness watcher needs a source to watch (F8-state, 2026-11-22)
		ss.watchStop, ss.watchDone = make(chan struct{}), make(chan struct{})
		go ss.watchTunnels(ss.watchStop, ss.watchDone)
	}
	return ss, nil
}

// Stop ends the state's background watcher(s). Production runs the state for the process's whole life and
// never calls this; tests do, so a shrunk poll interval cannot leak a goroutine past the test.
func (ss *ScepterState) Stop() {
	ss.mu.Lock()
	ws, wd := ss.watchStop, ss.watchDone
	ss.watchStop, ss.watchDone = nil, nil
	ss.mu.Unlock()
	if ws != nil {
		close(ws)
		<-wd // the watcher is gone before this returns (tests restore the poll var after Stop)
	}
}

// scepterWatchPoll is the tunnel liveness watcher's cadence (F8-state, 2026-11-22): tunnels move up/down
// OUTSIDE scepter too (systemd stop, a crash, heal) — that changes the state document without a state_seq
// bump, and a seq-diffing client would never learn a tunnel died. The watcher diffs ScepterSource.Tunnels()
// against its last snapshot and fires tunnel_up/tunnel_down with via:"watch" (AddEvent bumps state_seq, so
// clients re-poll state.get). Var, not const: tests shrink it. Cadence cost on the default deployment: one
// Tunnels() read per 5 s per paired process — the same read state.get makes.
var scepterWatchPoll = 5 * time.Second

// scepterWatchEnt is one tunnel's entry in the liveness watcher's snapshot (round-2 fixes 8/9, 2026-11-22):
// up is the last-OBSERVED direction; fired/firedAt the direction and moment the SCEPTER path last announced
// a tunnel_up/tunnel_down for the tunnel (zero time = none) — a flip matching that announcement within
// 2×poll is the scepter op's own state change, not news; miss counts consecutive polls the tunnel was
// absent from the listing.
type scepterWatchEnt struct {
	up      bool
	fired   bool
	firedAt time.Time
	miss    int
}

// watchAnnounced records that the SCEPTER path just fired a liveness event for name in direction up
// (tunnel.start/stop/restart's tunnel_up/tunnel_down, tunnel.create's tunnel_up). The watcher's next poll
// would otherwise see the op's own state flip and announce it again via:"watch" — one state change, two
// events (round-2 fix 8, 2026-11-22). Real flips keep firing.
func (ss *ScepterState) watchAnnounced(name string, up bool) {
	ss.mu.Lock()
	if ss.watchSnap == nil {
		ss.watchSnap = map[string]scepterWatchEnt{}
	}
	e := ss.watchSnap[name]
	e.fired, e.firedAt = up, ss.nowf()
	ss.watchSnap[name] = e
	ss.mu.Unlock()
}

// watchGone records a tunnel the SCEPTER path removed (tunnel.delete): tunnel_deleted announced the end, so
// the liveness watcher must not add a tunnel_down when the listing stops carrying the name — the last-known
// state is preset to down and the two-miss rule then drops it silently.
func (ss *ScepterState) watchGone(name string) {
	ss.mu.Lock()
	if ss.watchSnap == nil {
		ss.watchSnap = map[string]scepterWatchEnt{}
	}
	e := ss.watchSnap[name]
	e.up, e.fired, e.firedAt = false, false, ss.nowf()
	ss.watchSnap[name] = e
	ss.mu.Unlock()
}

// watchTunnels is the liveness watcher (F8-state): polls the source, diffs state/health per tunnel against
// the last snapshot, fires the up/down events OUTSIDE the state lock (AddEvent locks it itself). A tunnel
// seen for the first time records its baseline silently — the create path already fired its own event. A
// flip the scepter path announced itself within the window is skipped (round-2 fix 8). A tunnel missing
// from the listing is treated as gone only on the SECOND consecutive miss (round-2 fix 9, 2026-11-22): a
// one-poll listing hiccup must not re-baseline it — reappearing after one miss keeps its history and diffs
// normally — and the second miss fires tunnel_down why:"gone" when it was last known up, unless the scepter
// path announced the tunnel's end within the window (a stop or the delete's watchGone: already news).
func (ss *ScepterState) watchTunnels(ws, wd chan struct{}) {
	// both channels are passed in, never read from ss: Stop nils the struct fields under the lock, and an
	// unlocked field read here raced that nil-out under -race
	defer close(wd)
	for {
		select {
		case <-ws:
			return
		case <-time.After(scepterWatchPoll):
		}
		ss.mu.Lock()
		src := ss.src
		ss.mu.Unlock()
		if src == nil {
			return
		}
		snap := map[string]bool{}
		for _, t := range src.Tunnels() {
			snap[t.Name] = t.State == "active" && t.Health != "down"
		}
		type flip struct {
			name string
			up   bool
		}
		var fires []flip
		var gone []string
		ss.mu.Lock()
		next := make(map[string]scepterWatchEnt, len(snap))
		now := ss.nowf()
		for name, up := range snap {
			prev, seen := ss.watchSnap[name]
			e := scepterWatchEnt{up: up, fired: prev.fired, firedAt: prev.firedAt}
			if seen && prev.up != up &&
				!(prev.fired == up && !prev.firedAt.IsZero() && now.Sub(prev.firedAt) < 2*scepterWatchPoll) {
				fires = append(fires, flip{name, up})
			}
			next[name] = e
		}
		for name, prev := range ss.watchSnap {
			if _, present := snap[name]; present {
				continue
			}
			prev.miss++
			if prev.miss < 2 {
				next[name] = prev // one miss keeps lastSeen: a reappearance keeps its history (round-2 fix 9)
				continue
			}
			// second miss: gone. Announced ends (the delete's watchGone, a stop within the window) already
			// fired their event; a unit that vanished outside scepter while last known up is news.
			recentlyEnded := !prev.firedAt.IsZero() && now.Sub(prev.firedAt) < 2*scepterWatchPoll && !prev.fired
			if prev.up && !recentlyEnded {
				gone = append(gone, name)
			}
		}
		ss.watchSnap = next
		ss.mu.Unlock()
		for _, f := range fires {
			if f.up {
				ss.AddEvent(EvTunnelUp, map[string]any{"name": f.name, "via": "watch"})
			} else {
				ss.AddEvent(EvTunnelDown, map[string]any{"name": f.name, "via": "watch"})
			}
		}
		for _, name := range gone {
			ss.AddEvent(EvTunnelDown, map[string]any{"name": name, "via": "watch", "why": "gone"})
		}
	}
}

// cred snapshots the credential under the state lock: ReloadPairing swaps it (revocation/rotation), so no
// reader may dereference ss.pair outside the lock.
func (ss *ScepterState) cred() (uuid string, caps uint32) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.pair == nil {
		return "", 0
	}
	return ss.pair.UUIDString(), ss.pair.Caps
}

// ReloadPairing swaps the pairing credential — the ENGINE side of the plan security requirement
// "revocation is instant and local" (F8-revoke, 2026-11-22; the .pairing poller that calls it lives in
// cmd/wattun): future commands are checked against the NEW credential (uuid/caps; a live stream's per-command
// cap check re-reads it). p == nil disarms: the state turns unpaired, every live scepter stream is reset
// mid-line (the cockpit's in-flight call errors; a client cannot tell that from a link cut — by design, the
// channel is dead either way), and new sid-0 service is refused (serveScepterLoop). The tunnel PSK is
// untouched: sessions and user streams keep running — only the management plane dies. pair_rotated /
// pair_revoked fire here so the ring records the event even with the channel already gone.
func (ss *ScepterState) ReloadPairing(p *PairingConfig) {
	ss.mu.Lock()
	old := ss.pair
	ss.pair = p
	var lives []*Stream
	for st := range ss.lives {
		lives = append(lives, st)
	}
	ss.mu.Unlock()
	if p == nil {
		for _, st := range lives { // outside ss.mu: Reset takes the session lock (lock order: never ss.mu → session)
			st.Reset()
		}
	}
	if old == nil && p == nil {
		return // nothing was paired and nothing changed
	}
	why := EvPairRotated
	u := p
	if p == nil {
		why, u = EvPairRevoked, old
	}
	if ss.audit != nil && u != nil {
		ss.audit.record(ss.nowf(), u.UUIDString(), why, "reload", CodeOK)
	}
	ss.AddEvent(why, map[string]any{"uuid": uuidOf(u)})
}

func uuidOf(p *PairingConfig) string {
	if p == nil {
		return ""
	}
	return p.UUIDString()
}

// SetOps arms the write side (phase B). Without it every write command answers unknown_cmd — a phase-A binary,
// or a deployment that wants the read-only cockpit only. Call once at startup, before any scepter stream is
// served; the binary wires the real ops in main, tests inject a fake. With armed ops and a persistent journal
// dir it also starts the update-status watcher (phase D): the update job's outcome travels across the engine
// restart in the .update.status mailbox file, and this watcher is what turns it into events after revival.
func (ss *ScepterState) SetOps(ops ScepterOps) {
	ss.mu.Lock()
	ss.ops = ops
	ss.mu.Unlock()
	if ops != nil && ss.statusPath() != "" && ss.updateWatch.CompareAndSwap(false, true) {
		go ss.watchUpdateStatus()
	}
}

// statusPath is the update mailbox next to the journal (same config dir). Empty when there is no persistent
// journal (tests, ephemeral pairing): no file, no watcher.
func (ss *ScepterState) statusPath() string {
	if ss.journal == nil || ss.journal.path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(ss.journal.path), ScepterUpdateStatusFile)
}

// scepterEvSubject picks the coalescing subject of an event (plan E.1): the tunnel name when the event is
// about one (tunnel_up/down/edited/deleted, heal_action, carrier_switched), else the object id (probe
// open/close, update runs), else the pair itself (scepter_up/down, auto_test). Repeats about the SAME
// subject inside the window are the flood the plan caps; different subjects never coalesce against each
// other, so two probes opened in one second both land in the ring.
func scepterEvSubject(detail map[string]any) string {
	for _, k := range []string{"name", "id", "run"} {
		if s, ok := detail[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// AddEvent records a state change and returns its seq (the state_seq counter increments on EVERY change —
// a coalesced event still moves the cursor, so a client that diffs by seq sees that state moved and
// re-polls state.get). Coalescing (plan E.1): at most one event per evWindow per (type, subject) reaches
// the ring; a repeat is DROPPED, never queued. Backpressure rule (plan E.1): drop HISTORY first, never
// commands — a full ring evicts its oldest entries, and nothing here can block or refuse a command: the
// check is two map lookups under the lock AddEvent already holds, there is no channel and no consumer
// goroutine between the producers and the ring (the only reader, events.since, copies under this same
// lock), so the command queue (qmu) never waits on event traffic.
func (ss *ScepterState) AddEvent(kind string, detail map[string]any) uint64 {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.seq++
	key := kind + "\x00" + scepterEvSubject(detail)
	now := ss.nowf()
	if len(ss.evFire) > scepterEvKeys {
		for k, t := range ss.evFire { // bound the table: expired entries cannot coalesce anything (above)
			if now.Sub(t) >= ss.evWindow {
				delete(ss.evFire, k)
			}
		}
	}
	if last, ok := ss.evFire[key]; ok && now.Sub(last) < ss.evWindow {
		return ss.seq // coalesced: dropped, not queued — the ring keeps the last full-fidelity event per window
	}
	ss.evFire[key] = now
	ev := ScepterEvent{Seq: ss.seq, Type: kind, TS: now.Unix(), Detail: detail}
	ss.events = append(ss.events, ev)
	if len(ss.events) > scepterEvents {
		ss.events = ss.events[len(ss.events)-scepterEvents:] // history is what gets dropped, never commands
	}
	return ev.Seq
}

// StateSeq reports the current state_seq.
func (ss *ScepterState) StateSeq() uint64 {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.seq
}

// document builds the versioned state document (plan: engine version, pairing UUID + caps, tunnel list, event
// cursor, uptime, state_seq). One JSON object; clients diff by seq.
func (ss *ScepterState) document() map[string]any {
	ss.mu.Lock()
	seq, up, cursor := ss.seq, ss.nowf().Sub(ss.started)/time.Second, uint64(0)
	if len(ss.events) > 0 {
		cursor = ss.events[len(ss.events)-1].Seq
	}
	pair := ss.pair
	ss.mu.Unlock()
	doc := map[string]any{
		"v": scepterV, "ver": Version, "state_seq": seq, "uptime_s": up, "event_cursor": cursor,
		"pair": map[string]any{"uuid": pair.UUIDString(), "caps": CapName(pair.Caps), "caps_mask": pair.Caps},
	}
	if ss.src != nil {
		doc["tunnels"] = ss.src.Tunnels()
	} else {
		doc["tunnels"] = []ScepterTunnelInfo{}
	}
	return doc
}

// ---- command registry (phase A: read-only) ----

type scepterHandler func(ss *ScepterState, req ScepterRequest) (map[string]any, int)

type scepterCmd struct {
	minCap   uint32
	fn       scepterHandler
	needsOps bool // a phase-B write intent: unknown_cmd while no ScepterOps is armed (phase-A server)
}

// scepterCmds is the registry. Every entry names its minimum capability and the check runs SERVER-side on every
// command (client-side gating is UX, not security — plan security requirement). Phase A read split: hello/ping
// answer any credential (they reveal only liveness), the pairing's own state (state.get/tunnels.list) answers
// CapTunnel, and everything that reads live telemetry (stats/logs/events/history) needs CapManage per D4
// ("manage: +edit/delete/test/stats/events"). Phase B write split (plan B.1): create is CapCreate, everything
// that changes an existing tunnel is CapManage.
var scepterCmds = map[string]scepterCmd{
	"scepter.hello": {minCap: CapTunnel, fn: cmdHello},
	"scepter.ping":  {minCap: CapTunnel, fn: cmdPing},
	"state.get":     {minCap: CapTunnel, fn: cmdStateGet},
	"tunnels.list":  {minCap: CapTunnel, fn: cmdTunnelsList},
	"tunnel.stats":  {minCap: CapManage, fn: cmdTunnelStats},
	"tunnel.logs":   {minCap: CapManage, fn: cmdTunnelLogs},
	"events.since":  {minCap: CapManage, fn: cmdEventsSince},
	"history":       {minCap: CapManage, fn: cmdHistory},

	"tunnel.create":    {minCap: CapCreate, fn: cmdTunnelCreate, needsOps: true},
	"tunnel.edit":      {minCap: CapManage, fn: cmdTunnelEdit, needsOps: true},
	"tunnel.delete":    {minCap: CapManage, fn: cmdTunnelDelete, needsOps: true},
	"tunnel.start":     {minCap: CapManage, fn: cmdTunnelUnit("start"), needsOps: true},
	"tunnel.stop":      {minCap: CapManage, fn: cmdTunnelUnit("stop"), needsOps: true},
	"tunnel.restart":   {minCap: CapManage, fn: cmdTunnelUnit("restart"), needsOps: true},
	"limits.set":       {minCap: CapManage, fn: cmdLimitsSet, needsOps: true},
	"limits.reset":     {minCap: CapManage, fn: cmdLimitsReset, needsOps: true},
	"preset.list":      {minCap: CapManage, fn: cmdPresetList}, // the catalog is engine-owned: no ops, no phase-B server needed
	"preset.apply":     {minCap: CapManage, fn: cmdPresetApply, needsOps: true},
	"tunnel.keyrotate": {minCap: CapManage, fn: cmdTunnelKeyRotate, needsOps: true},

	// U0 audit coverage (2026-11-23): the credential rotates itself at the same tier (a credential may
	// always rotate; caps CHANGES stay a Kharej-console action, plan D3), and the bonded-path / quota
	// runtime ops ride the tunnel's own metrics server. New commands are registry entries only — an old
	// peer never opens sid 0 toward them (the mixed-version rule), so the wire contract is unchanged.
	"pair.rotate":  {minCap: CapManage, fn: cmdPairRotate, needsOps: true},
	"carrier.mute": {minCap: CapManage, fn: cmdCarrierMute, needsOps: true},

	// Phase C (remote carrier work): probe listeners, the link-verified carrier change and the fleet auto-test.
	"test.open":      {minCap: CapManage, fn: cmdTestOpen, needsOps: true},
	"test.close":     {minCap: CapManage, fn: cmdTestClose, needsOps: true},
	"carrier.change": {minCap: CapManage, fn: cmdCarrierChange, needsOps: true},
	"auto.test":      {minCap: CapManage, fn: cmdAutoTest, needsOps: true},
	"auto.rows":      {minCap: CapManage, fn: cmdAutoRows, needsOps: true},
	"auto.apply":     {minCap: CapManage, fn: cmdAutoApply, needsOps: true},

	// Phase D (operations). doctor.fetch answers from the state itself (basic doc) and is enriched by the
	// ops when armed — deliberately NOT needsOps. The update pair and the config-dir reads are ops-only.
	"update.status": {minCap: CapManage, fn: cmdUpdateStatus, needsOps: true},
	"update.run":    {minCap: CapFull, fn: cmdUpdateRun, needsOps: true}, // the one CapFull command (plan D4)
	"doctor.fetch":  {minCap: CapManage, fn: cmdDoctorFetch},
	"backup.export": {minCap: CapManage, fn: cmdBackupExport, needsOps: true},
	"audit.tail":    {minCap: CapManage, fn: cmdAuditTail, needsOps: true},
}

// Handle validates and runs one request. Order (each step is a trust-boundary check, cheapest first):
// registry → ops presence → rate → capability → journal replay (idempotency) → id-cmd conflict → TTL →
// execute → journal. The capability check precedes the replay (round-2 fix 3, 2026-11-22): a rotated
// lower-cap credential must not replay an outcome recorded under higher caps.
// The caller stamps Seq. EVERY outcome is audited (plan E.3): the wrapper appends one ScepterAuditFile line
// with the credential UUID for ok/denied/stale/rate_limited/bad_request/unknown alike — "who tried what" is
// answerable from the audit alone — while the journal inside stays outcomes-only for replay. The audit write
// runs AFTER handle returned (the command queue is released), so the queue never waits on audit I/O either.
func (ss *ScepterState) Handle(req ScepterRequest, caps uint32) ScepterResponse {
	resp := ss.handle(req, caps)
	uuid, _ := ss.cred()
	ss.audit.record(ss.nowf(), uuid, req.Cmd, req.ID, resp.Code)
	return resp
}

func (ss *ScepterState) handle(req ScepterRequest, caps uint32) ScepterResponse {
	c, ok := scepterCmds[req.Cmd]
	if req.ID == "" || !ok {
		return ScepterResponse{ID: req.ID, Code: CodeUnknownCmd}
	}
	now := ss.nowf()
	ss.mu.Lock()
	ops := ss.ops // snapshotted under the lock: SetOps races nothing
	ss.mu.Unlock()
	if c.needsOps && ops == nil {
		// a phase-A server (or a reads-only deployment): the write commands do not exist here. Answered
		// before the rate bucket so probing writes cannot drain a reader's command budget.
		return ScepterResponse{ID: req.ID, Code: CodeUnknownCmd}
	}
	ss.mu.Lock()
	rl := ss.rate.allow(now)
	ss.mu.Unlock()
	if !rl {
		return ScepterResponse{ID: req.ID, Code: CodeRateLimited}
	}
	if caps&c.minCap == 0 {
		// BEFORE the journal replay (round-2 fix 3, 2026-11-22): a rotated lower-cap credential must not
		// replay a recorded outcome granted under higher caps — capability is judged fresh on every command,
		// retries included.
		return ScepterResponse{ID: req.ID, Code: CodeDenied, Params: map[string]any{"need": CapName(c.minCap)}}
	}
	// ONE command queue per pairing (plan B.4/E.2, the bash manager's mgr_lock pattern): from the idempotency
	// replay to the journal record the whole command holds one mutex, so two scepter streams never interleave
	// write intents, a retry racing its original cannot double-apply, and Kharej's files are touched by one
	// intent at a time. The rate bucket stays outside: flooding is rejected without queueing behind a restart.
	ss.qmu.Lock()
	defer ss.qmu.Unlock()
	if resp, ok := ss.journal.Lookup(req.ID, req.Cmd); ok && resp.ID == req.ID {
		resp.Seq = ss.StateSeq() // refresh the tail: the client may have been offline a while
		return resp
	}
	if ss.journal.Conflict(req.ID, req.Cmd) {
		// the id is already recorded for a DIFFERENT command (round-2 fix 1, 2026-11-22): re-recording over
		// it would erase the original command's outcome and its legit retry would miss and re-execute a
		// mutation (double-apply). Answer without recording — the stored outcome stays for the original
		// command's retry.
		return ScepterResponse{ID: req.ID, Code: CodeBadRequest,
			Params: map[string]any{"why": "command id reused with a different command"}}
	}
	ttl := req.TTL
	if n, ok := argInt(req.Args, "ttl_s"); !ok {
		// ttl_s (plan's intent shape) is the args alias of the wire `ttl` field, reserved on every command;
		// strictly-typed args rule: a wrong type is bad_request WHENEVER it is present, wire ttl set or not
		// (round-2 fix 4, 2026-11-22 — the check used to be skipped when the wire ttl was set).
		return ScepterResponse{ID: req.ID, Code: CodeBadRequest}
	} else if ttl == 0 && n > 0 {
		ttl = n // the args alias resolves only an unset wire ttl, as before
	}
	if ttl == 0 {
		ttl = scepterTTL
	}
	ttl = intentTTLClamp(ttl) // the client does not set its own window (F6/L6, 2026-11-22)
	ts := req.TS
	if ts == 0 {
		ts = now.Unix() // an id-less clock: treat as fresh (the journal still dedups)
	} else if ts > now.Unix()+int64(scepterSkew/time.Second) {
		// minted in the future: the server does not honor future minting (F6/L6, 2026-11-22) — the intent is
		// judged from NOW at this check, so it can never be both future-dated and expired, and what the
		// journal and the doctor's trace record is the server's clock. The horizon stays finite either way:
		// ttl is clamped above, so the intent expires no later than its claimed ts + intentTTLMax + skew.
		ts = now.Unix()
	}
	if now.After(time.Unix(ts, 0).Add(time.Duration(ttl)*time.Second + scepterSkew)) {
		return ScepterResponse{ID: req.ID, Code: CodeStale}
	}
	params, code := func() (params map[string]any, code int) {
		defer func() {
			if r := recover(); r != nil {
				// a panicking handler (an ops bug) must not take the engine down (L3, 2026-11-22): answer
				// CodeInternal like any Kharej-side op failure. It is NOT journaled (round-2 fix 2): the
				// panic unwound PAST the ops' rollback, so the outcome describes half-applied state —
				// journaling it would replay the failure forever. The fresh attempt is the recovery: it
				// completes the config or meets the name_taken/rollback path like any first run.
				params = map[string]any{"detail": fmt.Sprintf("panic: %v", r)}
				code = CodeInternal
			}
		}()
		return c.fn(ss, req)
	}()
	resp := ScepterResponse{ID: req.ID, Code: code, Params: params}
	if params == nil {
		resp.Params = nil
	}
	if scepterMutations[req.Cmd] && code == CodeOK { // MUTATING intents, APPLIED outcomes only
		// (H1/F4, 2026-11-22 — reads re-execute; journaling them once grew the replay set without bound and
		// stale-replayed a hello across an engine update. Round-2 fix 2, 2026-11-22 — failures re-execute
		// too: a journaled failure (the panic guard's CodeInternal, or a rolled-back op) replayed forever,
		// and a replay cannot recover half-applied state. Every non-OK outcome is re-executable by design —
		// the rollback makes a re-run safe, and a re-run is exactly the recovery when a panic skipped the
		// rollback. Pure rejections (denied/stale/rate/bad args/not found) are recomputed on a retry anyway.)
		ss.journal.Record(req.Cmd, req.ID, ts, resp)
	}
	ss.mu.Lock() // every handled request (success or code) is visible to the doctor's last-commands trace
	ss.recent = append(ss.recent, ScepterRec{Cmd: req.Cmd, Code: code, TS: ts})
	if len(ss.recent) > scepterRecent {
		ss.recent = ss.recent[1:]
	}
	ss.mu.Unlock()
	return resp
}

// Recent returns the last handled commands, oldest first (doctor output only — never /stats, plan D2's
// hidden-infrastructure rule).
func (ss *ScepterState) Recent() []ScepterRec {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := make([]ScepterRec, len(ss.recent))
	copy(out, ss.recent)
	return out
}

// PairingInfo reports the pairing UUID and capability mask for the local /scepter doctor endpoint.
func (ss *ScepterState) PairingInfo() (uuid string, caps uint32) {
	return ss.cred()
}

// args helpers: strictly-typed reads, wrong types are bad_request rather than reflected into anything.

func argString(args map[string]any, key string) (string, bool) {
	if args == nil {
		return "", false
	}
	v, ok := args[key]
	if !ok {
		return "", true // absent: the zero value
	}
	s, ok := v.(string)
	return s, ok
}

func argInt(args map[string]any, key string) (int, bool) {
	if args == nil {
		return 0, true
	}
	v, ok := args[key]
	if !ok {
		return 0, true
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// argStringMap reads an object of scalar values as strings (create/edit params and patches): absent is the
// zero value, numbers and booleans are stringified (JSON clients send whatever is convenient), any other
// shape is bad_request.
func argStringMap(args map[string]any, key string) (map[string]string, bool) {
	if args == nil {
		return nil, true
	}
	v, ok := args[key]
	if !ok {
		return nil, true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, e := range m {
		s, ok := argScalar(e)
		if !ok {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}

// argStringSlice reads an array of scalars as strings (edit's drop list, limits.set's items).
func argStringSlice(args map[string]any, key string) ([]string, bool) {
	if args == nil {
		return nil, true
	}
	v, ok := args[key]
	if !ok {
		return nil, true
	}
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, e := range a {
		s, ok := argScalar(e)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func argScalar(v any) (string, bool) {
	switch n := v.(type) {
	case string:
		return n, true
	case float64:
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10), true
		}
		return strconv.FormatFloat(n, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(n), true
	}
	return "", false
}

// intentTTLBounds is the intent-TTL window the server clamps the client's request into (F6/L6, 2026-11-22):
// a 60 s floor (a shorter one races the retry it was minted for), a 1 h ceiling (a client-chosen ttl must not
// outlive an outage), the 600 s default unchanged in between.
const (
	intentTTLMin = 60
	intentTTLMax = 3600
)

func intentTTLClamp(ttl int) int {
	switch {
	case ttl < intentTTLMin:
		return intentTTLMin
	case ttl > intentTTLMax:
		return intentTTLMax
	}
	return ttl
}

// cmdHello is the pairing hello exchange (plan phase A item 2): the request's args carry the client's ver/caps
// (informational — the response's own ver is authoritative for the version decision, made by DialScepter).
func cmdHello(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	uuid, caps := ss.cred()
	return map[string]any{
		"ver": Version, "v": scepterV, "caps": CapName(caps), "uuid": uuid, "state_seq": ss.StateSeq(),
	}, CodeOK
}

func cmdPing(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	return map[string]any{"pong": true}, CodeOK
}

func cmdStateGet(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	return ss.document(), CodeOK
}

func cmdTunnelsList(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	if ss.src == nil {
		return map[string]any{"tunnels": []ScepterTunnelInfo{}}, CodeOK
	}
	return map[string]any{"tunnels": ss.src.Tunnels()}, CodeOK
}

func cmdTunnelStats(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	if ss.src == nil {
		return nil, CodeNotFound
	}
	m, found := ss.src.TunnelStats(name)
	if !found {
		return nil, CodeNotFound
	}
	return m, CodeOK
}

// cmdTunnelLogs: the one Phase A payload that can be large, so the serve loop chunks it (see writeResp). tail
// defaults to 100, capped at 1000 — a bound on both the read and the response fan-out.
func cmdTunnelLogs(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	tail, ok := argInt(req.Args, "tail")
	if !ok || tail < 0 {
		return nil, CodeBadRequest
	}
	if tail == 0 {
		tail = 100
	}
	tail = min(tail, 1000)
	if ss.src == nil {
		return map[string]any{"logs": []string{}}, CodeOK
	}
	logs, found := ss.src.TunnelLogs(name, tail)
	if !found {
		return nil, CodeNotFound
	}
	return map[string]any{"logs": logs}, CodeOK
}

func cmdEventsSince(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	since, ok := argInt(req.Args, "seq")
	if !ok || since < 0 {
		return nil, CodeBadRequest
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	var out []ScepterEvent
	for _, ev := range ss.events {
		if ev.Seq > uint64(since) {
			out = append(out, ev)
		}
	}
	if out == nil {
		out = []ScepterEvent{}
	}
	cursor := uint64(0)
	if len(ss.events) > 0 {
		cursor = ss.events[len(ss.events)-1].Seq
	}
	return map[string]any{"events": out, "cursor": cursor}, CodeOK
}

func cmdHistory(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	if ss.src == nil {
		return nil, CodeNotFound
	}
	h, found := ss.src.History(name)
	if !found {
		return nil, CodeNotFound
	}
	return map[string]any{"history": h}, CodeOK
}

// ---- write intents (phase B, plan B.1/B.2) ----
//
// Every write command is validate → backup → apply → verify → report, with the ops source owning Kharej's
// reality (tunnel files, units, port bookkeeping). This engine layer stays deliberately thin: argument typing,
// the per-pair create bucket, the event, and the base_seq tail. Rejections come back as machine codes from the
// ops (validation is Kharej's, plan B.2); a rolled-back write is CodeInternal with {"rolled_back":true}.
// Failed outcomes are NOT journaled (round-2 fix 2, 2026-11-22): a retry re-runs the op — the rollback makes
// that safe, and a re-run is also how a panic-skipped rollback recovers — while APPLIED outcomes replay from
// the journal (Handle).

// ScepterTunnelSpec is one tunnel.create intent, typed. The name is optional (Kharej picks one), Key is
// engine-generated (the created tunnel's new PSK, delivered to the cockpit inside the session AEAD), Params
// are extra config keys (flag names) written verbatim into the yml. Ports is the ports: list in the token's
// field-7 shape: "20030,8443:443/udp", ranges included.
type ScepterTunnelSpec struct {
	Name    string
	Carrier string
	Ports   string
	Params  map[string]string
	Key     string
}

// ScepterPatch is one tunnel.edit / preset.apply intent: top-level config keys to set, keys to drop, and an
// optional replacement ports: list. All empty is rejected by the handler (an empty patch would restart the
// unit for nothing).
type ScepterPatch struct {
	Set   map[string]string
	Drop  []string
	Ports string
}

// ScepterOps is the write side of the management plane (plan B.1: validate → backup → apply → verify →
// report; failures roll back). Implemented over /etc/wattun + systemd by cmd/wattun/scepter_ops.go; tests
// inject a fake over a temp CONF dir. Handlers call it with the command queue held (one intent at a time), so
// implementations need no locking of their own. Every method answers (params, code) in response codes.
type ScepterOps interface {
	Create(spec ScepterTunnelSpec) (map[string]any, int)
	Edit(name string, patch ScepterPatch) (map[string]any, int)
	Delete(name string) (map[string]any, int)
	Unit(name, action string) (map[string]any, int) // action: "start" | "stop" | "restart"
	SetLimits(name string, items []string) (map[string]any, int)

	// Phase C (remote carrier work). TestOpen serves a probe listener of one carrier shape for ttlS seconds and
	// reports what the cockpit should dial (id, port, key, path); TestClose closes it early. CarrierChange is
	// the edit path plus a link check of the new shape with automatic rollback. AutoTest triggers the ranking
	// run and returns BEFORE it finishes — done is called with (rows ok, rows total) when the run completes;
	// AutoRows reads the stored table; ApplyRow pushes row N (1-based, ranked) through CarrierChange.
	TestOpen(carrier string, ttlS int) (map[string]any, int)
	TestClose(id string) (map[string]any, int)
	CarrierChange(name, carrier string, params map[string]string) (map[string]any, int)
	AutoTest(mode string, done func(ok, total int)) (map[string]any, int)
	AutoRows() (map[string]any, int)
	ApplyRow(name string, row int) (map[string]any, int)

	// Phase D (operations). UpdateStatus reports engine version, wattun.prev presence, unit states and the
	// update mailbox — local reads only, never a network fetch. UpdateRun starts Kharej's own update
	// (CapFull ONLY; the ops stage a verified release and hand the swap to a job that outlives the engine
	// restart) and returns before anything moves. Doctor returns the ops-side doctor fragments (latch, unit,
	// update mailbox, journal) merged into doctor.fetch. BackupExport returns a tarball of the config dir
	// as params {"logs":[doc]} (doc: b64/sha256/size/files) so the serve loop chunks it like tunnel.logs.
	// AuditTail returns the last n lines of the pairing audit and the scepter journal, same logs convention.
	UpdateStatus() (map[string]any, int)
	UpdateRun(to string) (map[string]any, int)
	Doctor() (map[string]any, int)
	BackupExport() (map[string]any, int)
	AuditTail(n int) (map[string]any, int)

	// U0 audit coverage (2026-11-23). KeyRotate swaps a tunnel's PSK (the edit drill: backup → mint →
	// rewrite yml+key+token → restart → verify, rollback on failure) and answers the rebuilt wat1: token
	// (the cockpit needs it to update the Iran side, which still runs on the old key). PairRotate rewrites
	// the .pairing store (same UUID+caps, new 32-byte key, the manager's oldkey/window comment contract)
	// and answers the new watp1: line — the state adopts it via ReloadPairing so the live channel keeps
	// serving. Mute flips a bonded path's manual mute over the tunnel's local metrics server (the bash
	// console's POST /carrier/toggle); ResetLimits resets quota counters the same way (POST /quota/reset).
	// pair.revoke stays Kharej-local BY DESIGN (plan D3's trust boundary): the channel must not be able to
	// revoke itself — do not add it.
	KeyRotate(name string) (map[string]any, int)
	PairRotate(windowS int) (map[string]any, int)
	Mute(name, carrier string, mute bool) (map[string]any, int)
	ResetLimits(name string, port int) (map[string]any, int)
}

// ValidScepterName is the tunnel-name rule: a name becomes the systemd instance (wattun@NAME) and the config
// path ($CONF/NAME.yml), so it stays inside [A-Za-z0-9_-]{1,32} — byte-for-byte the shape wattun-manager's
// v_name enforces (wattun-manager v_name, line ~1528: `^[a-zA-Z0-9_-]{1,32}$`; dashes in ordinary names ARE
// allowed there, so no dash is banned here). One extra ban on top, from the manager's LISTING rules: a name
// ending in "-r" is the auto reverse companion shape — companion_of (wattun-manager:4291-4296) strips
// "${name%-r}" and is_auto_helper (562-563) hides such units from every tunnel listing when the parent is an
// auto Kharej tunnel — so a cockpit-created "x-r" could exist on Kharej yet never show in the manager. v_name
// itself bans nothing; the hide is conditional on the parent, but the collision shape is exactly "suffix
// after the last '-' == r", so that is what is rejected here (F12-name, 2026-11-22).
func ValidScepterName(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return !strings.HasSuffix(name, "-r")
}

// ScepterNewKey generates a tunnel PSK: 40 alphanumerics, the manager's new_key shape (32 urandom bytes
// stripped of base64 punctuation). It travels to the cockpit inside the session AEAD only — tunnel.create
// uses it for the created tunnel, the phase C ops for probe listeners.
func ScepterNewKey() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 40)
	if _, err := crand.Read(b); err != nil {
		return "" // crypto/rand never fails on Linux/Windows; an empty key is rejected by the ops' yml check
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// scepterPreset is one catalog entry: the pure key-patch preset.apply pushes through the edit path, and the
// one-line description preset.list serves (the panel and the TUI read the same list).
type scepterPreset struct {
	patch ScepterPatch
	desc  string
}

// scepterPresets is the preset.apply catalog (plan B.1): the bash manager's anti-censor presets
// (wattun-manager apply_preset, mirrored 2026-11-23 — TestScepterPresetCatalog pins the mirror) as pure
// key-patches, plus the shaping pair. Values are long-shipped config keys (flag names) so a preset cannot
// name a knob an existing unit would fail to parse; a preset goes through the edit path, so a unit that
// still refuses to come up rolls back like any edit. The bash semantics per key are "set when non-empty,
// unset when empty" — a static patch expresses the unset half as an unconditional drop, which is a no-op
// when the key is absent. Governor is the one asymmetry: the bash touches it only for icmp carriers (and
// always unsets it for off), so "off" drops it (inert on non-icmp carriers) while cf/rst-fast leave it
// alone, exactly like the bash. rst-fast sets sessions/conns like the bash; the bash skips them on a
// REVERSE tunnel (sessions > 1 is refused there), a static patch cannot — such a unit refuses its restart
// and the edit path rolls it back, the same protection any bad preset gets.
var scepterPresets = map[string]scepterPreset{
	"stealth": {patch: ScepterPatch{Set: map[string]string{"shape-data": "8", "noise": "med"}},
		desc: "pad stream packets (<=8% extra bytes) and send idle filler while quiet (shaping)"},
	"plain": {patch: ScepterPatch{Drop: []string{"shape-data", "noise"}},
		desc: "remove traffic shaping (back to the unshaped defaults)"},
	"cf": {patch: ScepterPatch{
		Set:  map[string]string{"fake-sni": "www.cloudflare.com", "fake-mode": "rst"},
		Drop: []string{"fake-ttl", "pool-rotate", "pool-rotate-bytes", "ech"}},
		desc: "Cloudflare edge: fake hello + bad-checksum RST, no churn (field-tested)"},
	"rst-fast": {patch: ScepterPatch{
		Set:  map[string]string{"fake-sni": "www.cloudflare.com", "fake-mode": "rst", "pool-rotate": "30m", "sessions": "4", "conns": "4"},
		Drop: []string{"fake-ttl", "pool-rotate-bytes", "ech"}},
		desc: "fastest direct: bad-checksum RST, 4 sessions of 4 conns, 30m pool rotation"},
	"mci": {patch: ScepterPatch{
		Set:  map[string]string{"fake-sni": "mci.ir", "fake-mode": "rst", "pool-rotate": "30m", "pool-rotate-bytes": "500MB", "ech": "ladder", "governor": "true"},
		Drop: []string{"fake-ttl"}},
		desc: "MCI (Hamrah Aval) whitelist: RST, ECH ladder, governor, 30m/500MB pool rotation"},
	"irancell": {patch: ScepterPatch{
		Set:  map[string]string{"fake-sni": "irancell.ir", "fake-mode": "seq", "pool-rotate": "20m", "pool-rotate-bytes": "300MB", "ech": "ladder", "governor": "true"},
		Drop: []string{"fake-ttl"}},
		desc: "Irancell/TCI whitelist: seq, ECH ladder, governor, 20m/300MB pool rotation"},
	"blackout": {patch: ScepterPatch{
		Set:  map[string]string{"fake-sni": "mci.ir", "fake-mode": "rst", "pool-rotate": "90s", "pool-rotate-bytes": "100MB", "ech": "ladder", "governor": "true"},
		Drop: []string{"fake-ttl"}},
		desc: "emergency blackout: aggressive RST, 90s pool rotation, ECH ladder, governor"},
	"low-churn": {patch: ScepterPatch{
		Set:  map[string]string{"fake-sni": "mci.ir", "fake-mode": "seq", "pool-rotate": "4h", "pool-rotate-bytes": "4GB", "ech": "auto", "governor": "true"},
		Drop: []string{"fake-ttl"}},
		desc: "conservative/low-churn: seq, 4h rotation for stable links under mild DPI"},
	"off": {patch: ScepterPatch{Drop: []string{"fake-sni", "fake-mode", "fake-ttl", "pool-rotate", "pool-rotate-bytes", "ech", "governor"}},
		desc: "clear every anti-censorship setting (plain dialing)"},
}

// cmdTunnelCreate: tunnel.create {name?, carrier, ports, params…, base_seq, ttl_s} (plan B.1).
func cmdTunnelCreate(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok {
		return nil, CodeBadRequest
	}
	carrier, ok := argString(req.Args, "carrier")
	if !ok || carrier == "" {
		return nil, CodeBadRequest
	}
	ports, ok := argString(req.Args, "ports")
	if !ok || ports == "" {
		return nil, CodeBadRequest
	}
	params, ok := argStringMap(req.Args, "params")
	if !ok {
		return nil, CodeBadRequest
	}
	if name != "" && !ValidScepterName(name) {
		// the same rule the manager enforces locally; Kharej re-checks (the ops own existence/caps)
		return map[string]any{"name": name}, CodeBadRequest
	}
	if !ss.createRate.allow(ss.nowf()) {
		return map[string]any{"resource": "create"}, CodeRateLimited
	}
	spec := ScepterTunnelSpec{Name: name, Carrier: carrier, Ports: ports, Params: params, Key: ScepterNewKey()}
	pre := ss.StateSeq() // the state_seq the intent met on arrival: base_seq is compared against THIS, not
	// the post-apply seq (which the event bump advanced by one — a matching base_seq must not carry the state)
	p, code := ss.ops.Create(spec)
	if code == CodeOK {
		ss.AddEvent(EvTunnelUp, map[string]any{"name": p["name"], "via": "scepter"})
		if n, is := p["name"].(string); is {
			ss.watchAnnounced(n, true) // the liveness watcher must not re-fire the create's own tunnel_up
		}
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// cmdTunnelEdit: tunnel.edit {name, set?, drop?, ports?, base_seq, ttl_s} — the plan's "patch…". carrier may
// be set (a carrier switch is an edit; phase C adds the link-verified change around it).
func cmdTunnelEdit(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	set, ok := argStringMap(req.Args, "set")
	if !ok {
		return nil, CodeBadRequest
	}
	drop, ok := argStringSlice(req.Args, "drop")
	if !ok {
		return nil, CodeBadRequest
	}
	ports, ok := argString(req.Args, "ports")
	if !ok {
		return nil, CodeBadRequest
	}
	if set == nil && drop == nil && ports == "" {
		return nil, CodeBadRequest
	}
	pre := ss.StateSeq() // see cmdTunnelCreate: base_seq is judged against the pre-apply seq
	p, code := ss.ops.Edit(name, ScepterPatch{Set: set, Drop: drop, Ports: ports})
	if code == CodeOK {
		if c, is := p["carrier"]; is && c != "" { // the ops echo the carrier only when the patch switched it
			ss.AddEvent(EvCarrierSwitched, map[string]any{"name": name, "carrier": c})
		} else {
			ss.AddEvent(EvTunnelEdited, map[string]any{"name": name})
		}
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// cmdTunnelDelete: tunnel.delete {name, confirm:"name"} — a destructive op repeats the name back (plan D3:
// reversible by construction; the ops keep .bak files, nothing is destroyed).
func cmdTunnelDelete(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	confirm, _ := argString(req.Args, "confirm")
	if !ok || name == "" || confirm != name {
		return nil, CodeBadRequest
	}
	p, code := ss.ops.Delete(name)
	if code == CodeOK {
		ss.AddEvent(EvTunnelDeleted, map[string]any{"name": name})
		ss.watchGone(name) // tunnel_deleted announced the end: the two-miss rule drops the name silently
	}
	return p, code
}

// cmdTunnelUnit builds the tunnel.start|stop|restart handlers (plan B.1). start/restart report a live unit,
// stop a stopped one; the verify is the ops' job, the event the engine's.
func cmdTunnelUnit(action string) scepterHandler {
	return func(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
		name, ok := argString(req.Args, "name")
		if !ok || name == "" {
			return nil, CodeBadRequest
		}
		p, code := ss.ops.Unit(name, action)
		if code == CodeOK {
			if action == "stop" {
				ss.AddEvent(EvTunnelDown, map[string]any{"name": name, "via": "scepter"})
				ss.watchAnnounced(name, false) // the watcher must not re-fire this flip via:"watch" (fix 8)
			} else {
				ss.AddEvent(EvTunnelUp, map[string]any{"name": name, "via": "scepter"})
				ss.watchAnnounced(name, true)
			}
		}
		return p, code
	}
}

// cmdLimitsSet: limits.set {name, limits:[…]} — the per-port rate/quota items in the yml's `limits:` syntax.
// Hot-reloaded by the unit's cfgWatcher, so this never restarts the unit (no channel cut, no dropped streams).
func cmdLimitsSet(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	if _, present := req.Args["limits"]; !present { // limits: [] clears every limit; absent args is bad_request
		return nil, CodeBadRequest
	}
	items, ok := argStringSlice(req.Args, "limits")
	if !ok {
		return nil, CodeBadRequest
	}
	p, code := ss.ops.SetLimits(name, items)
	if code == CodeOK {
		ss.AddEvent(EvTunnelEdited, map[string]any{"name": name, "limits": len(items)})
	}
	return p, code
}

// cmdPresetList: preset.list — the engine-owned catalog (name + one-line description). No ops: the catalog
// is static engine data, so a phase-A server answers it too, and every client (TUI, panel) reads the same
// list preset.apply accepts.
func cmdPresetList(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	names := make([]string, 0, len(scepterPresets))
	for n := range scepterPresets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"name": n, "desc": scepterPresets[n].desc})
	}
	return map[string]any{"presets": out}, CodeOK
}

// cmdPresetApply: preset.apply {name, preset} — a named patch from the engine-owned catalog through the edit
// path, so every client (TUI, panel) sees the same preset names and a preset rolls back like any edit.
func cmdPresetApply(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	preset, ok := argString(req.Args, "preset")
	if !ok || preset == "" {
		return nil, CodeBadRequest
	}
	ent, known := scepterPresets[preset]
	if !known {
		names := make([]string, 0, len(scepterPresets))
		for n := range scepterPresets {
			names = append(names, n)
		}
		sort.Strings(names)
		return map[string]any{"presets": strings.Join(names, ",")}, CodeBadRequest
	}
	pre := ss.StateSeq()
	p, code := ss.ops.Edit(name, ent.patch)
	if code == CodeOK {
		ss.AddEvent(EvTunnelEdited, map[string]any{"name": name, "preset": preset})
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// cmdTunnelKeyRotate: tunnel.keyrotate {name, base_seq?, ttl_s?} — the tunnel PSK rotates (U0 audit,
// 2026-11-23). The ops run the edit-shaped drill (backup → mint → rewrite yml+key+token atomically →
// restart → verify, rollback on failure) and answer the rebuilt wat1: token mirroring the manager's
// make_token with the NEW key and the tunnel's existing fields — the cockpit needs it to update the Iran
// side, which still runs on the old key. Event tunnel_edited {why:"keyrotate"}.
func cmdTunnelKeyRotate(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	pre := ss.StateSeq() // see cmdTunnelCreate: base_seq is judged against the pre-apply seq
	p, code := ss.ops.KeyRotate(name)
	if code == CodeOK {
		ss.AddEvent(EvTunnelEdited, map[string]any{"name": name, "why": "keyrotate"})
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// ---- U0 audit coverage (2026-11-23): the credential, the bond paths, the quota counters ----

// cmdPairRotate: pair.rotate {window_s?} — the pairing credential rotates ITSELF (a credential may always
// rotate at its own tier; caps CHANGES stay a Kharej-console action, plan D3). The ops rewrite the .pairing
// store (new key, same UUID+caps, the manager's oldkey/window comment contract) and answer the new watp1:
// line for the OTHER cockpits; this handler adopts the new credential here (ReloadPairing semantics) so
// future commands on the live channel are checked against it — the store poller would only catch up within
// its interval. The current channel keeps working (the stream is not reset; sessions key off the tunnel
// PSK, which is untouched) and the caller re-attaches its own stored line on its next start. The
// pair_rotated event fires from ReloadPairing; the store poller's later reload of the same credential is a
// second, harmless ring entry. Rate bucket: update-rate-like, one per 5 min (rotateRate).
func cmdPairRotate(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	window, ok := argInt(req.Args, "window_s")
	if !ok || window < 0 {
		return nil, CodeBadRequest
	}
	if !ss.rotateRate.allow(ss.nowf()) {
		return map[string]any{"resource": "pair.rotate"}, CodeRateLimited
	}
	p, code := ss.ops.PairRotate(window)
	if code == CodeOK {
		line, _ := p["watp1"].(string)
		np, perr := ParsePairingLine(line)
		if perr != nil || np == nil {
			// the ops wrote a store this engine cannot parse: answer, do not adopt (the next store poll
			// would disarm the channel — the ops bug is the caller's to fix, never a silent half-state)
			return map[string]any{"detail": "the ops returned an unparsable credential: " + perr.Error()}, CodeInternal
		}
		ss.ReloadPairing(np) // adopts for future commands; fires EvPairRotated; the live stream survives
	}
	return p, code
}

// cmdCarrierMute: carrier.mute {name, carrier, mute} — bonded-path mute/unmute. The bash console does it
// with a local POST to the tunnel's own metrics server (wattun-manager carrier_toggle_cmd); ops run on
// Kharej where that server is loopback-local, so the ops make the same call. `mute` is optional and
// strictly boolean (absent = false = unmute, the strictly-typed convention's zero value).
func cmdCarrierMute(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	carrier, ok := argString(req.Args, "carrier")
	if !ok || carrier == "" {
		return nil, CodeBadRequest
	}
	mute := false
	if v, present := req.Args["mute"]; present {
		b, isBool := v.(bool)
		if !isBool {
			return nil, CodeBadRequest
		}
		mute = b
	}
	return ss.ops.Mute(name, carrier, mute)
}

// cmdLimitsReset: limits.reset {name, port?} — quota reset over the tunnel's local metrics server, the bash
// console's "reset a port quota" (POST /quota/reset?port=N). port absent or 0 resets every quota'd port of
// the tunnel's limits: list. Not journaled (scepterMutations): a reset re-executes safely.
func cmdLimitsReset(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	port, ok := argInt(req.Args, "port")
	if !ok || port < 0 {
		return nil, CodeBadRequest
	}
	return ss.ops.ResetLimits(name, port)
}

// ---- remote carrier work (phase C) ----
//
// test.open / test.close / carrier.change / auto.test / auto.rows / auto.apply. The engine layer stays thin
// (arg typing, buckets, events, tails); the shapes, the link check and the measurement live in the ops —
// docs/TECHNICAL.md "Remote testing and carrier change" holds the version matrix (both ends 3.5.0) and the
// Iran-side restart contract.

// probeTTLBounds is the probe listener lifetime the handler clamps args ttl into: 10 s floor (a shorter one
// races its own client), 1 h ceiling (a forgotten probe must not own a port forever), 300 s default.
const (
	probeTTLDefault = 300
	probeTTLMin     = 10
	probeTTLMax     = 3600
)

func probeTTLClamp(ttl int) int {
	switch {
	case ttl <= 0:
		return probeTTLDefault
	case ttl < probeTTLMin:
		return probeTTLMin
	case ttl > probeTTLMax:
		return probeTTLMax
	}
	return ttl
}

// cmdTestOpen: test.open {carrier, ttl} — Kharej opens a probe listener of the requested shape (one carrier,
// no bonds, no raw sockets: a probe must be a thing a throw-away client can dial from Iran) and reports what
// to dial. The args ttl is the PROBE lifetime; the envelope's ttl/ttl_s field stays the intent TTL (Handle).
func cmdTestOpen(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	carrier, ok := argString(req.Args, "carrier")
	if !ok || carrier == "" {
		return nil, CodeBadRequest
	}
	ttl, ok := argInt(req.Args, "ttl")
	if !ok {
		return nil, CodeBadRequest
	}
	if !ss.probeRate.allow(ss.nowf()) {
		return map[string]any{"resource": "probe"}, CodeRateLimited
	}
	secs := probeTTLClamp(ttl)
	p, code := ss.ops.TestOpen(carrier, secs)
	if code == CodeOK {
		p["ttl"] = secs // echo the effective lifetime (the request's was clamped)
		ss.AddEvent(EvTestOpened, map[string]any{"carrier": carrier, "ttl": secs,
			"id": p["id"], "port": p["port"]})
	}
	return p, code
}

// cmdTestClose: test.close {probe} — close a probe listener before its ttl. The arg is "probe", not "id":
// the -scepter-call CLI lifts a top-level args["id"] as the command id (journal replay), so a probe id sent
// as "id" never reached this handler through the cockpit's transport (found by lane H, 2026-11-22).
func cmdTestClose(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	id, ok := argString(req.Args, "probe")
	if !ok || id == "" {
		return nil, CodeBadRequest
	}
	p, code := ss.ops.TestClose(id)
	if code == CodeOK {
		ss.AddEvent(EvTestClosed, map[string]any{"id": id, "why": "closed"})
	}
	return p, code
}

// cmdCarrierChange: carrier.change {name, carrier, params?, base_seq?, ttl_s?} — the auto_apply discipline
// remotely (plan C.1): apply the new carrier config, restart the unit, verify with a link check, and on any
// failure restore the .bak config and restart again, reporting rolled_back with the failure. The IRAN side of
// the restart is the cockpit's job (TECHNICAL.md contract): it rewrites its own tunnel and re-checks the link.
func cmdCarrierChange(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	carrier, ok := argString(req.Args, "carrier")
	if !ok || carrier == "" {
		return nil, CodeBadRequest
	}
	params, ok := argStringMap(req.Args, "params")
	if !ok {
		return nil, CodeBadRequest
	}
	if _, dup := params["carrier"]; dup { // the args carrier is authoritative; a duplicate is a client bug
		return map[string]any{"key": "carrier", "why": "pass the carrier as its own argument"}, CodeBadRequest
	}
	if !ss.createRate.allow(ss.nowf()) { // the structural bucket shared with tunnel.create
		return map[string]any{"resource": "carrier.change"}, CodeRateLimited
	}
	pre := ss.StateSeq() // see cmdTunnelCreate: base_seq is judged against the pre-apply seq
	p, code := ss.ops.CarrierChange(name, carrier, params)
	if code == CodeOK {
		ss.AddEvent(EvCarrierSwitched, map[string]any{"name": name, "carrier": carrier, "via": "carrier.change"})
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// cmdAutoTest: auto.test {mode?} — trigger the ranking run (mode "" or "plain": the plain shapes; "tls" adds
// the TLS family). Returns BEFORE the run finishes: read auto.rows for the table, EvAutoTested fires when it
// is done. A second trigger while one runs answers already_running, not an error.
func cmdAutoTest(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	var mode string
	if req.Args != nil { // argString(nil) is false by the strictly-typed convention; mode is OPTIONAL here
		var ok bool
		if mode, ok = argString(req.Args, "mode"); !ok {
			return nil, CodeBadRequest
		}
	}
	if !ss.autoRate.allow(ss.nowf()) {
		return map[string]any{"resource": "auto.test"}, CodeRateLimited
	}
	if mode == "" {
		mode = "plain" // the default catalog; the response and the event echo the resolved mode
	}
	p, code := ss.ops.AutoTest(mode, func(okRows, total int) {
		ss.AddEvent(EvAutoTested, map[string]any{"mode": mode, "ok": okRows, "total": total})
	})
	return p, code
}

// cmdAutoRows: auto.rows — the stored table of the last run (ranked: servable shapes first, by measured rate).
func cmdAutoRows(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	return ss.ops.AutoRows()
}

// cmdAutoApply: auto.apply {name, row} — apply ranked row N (1-based, the auto.rows order) to tunnel name
// through the carrier.change path, so the same link check and rollback guard a ranked switch.
func cmdAutoApply(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	name, ok := argString(req.Args, "name")
	if !ok || name == "" {
		return nil, CodeBadRequest
	}
	row, ok := argInt(req.Args, "row")
	if !ok || row < 1 {
		return nil, CodeBadRequest
	}
	if !ss.createRate.allow(ss.nowf()) { // the structural bucket: auto.apply restarts a unit
		return map[string]any{"resource": "auto.apply"}, CodeRateLimited
	}
	pre := ss.StateSeq()
	p, code := ss.ops.ApplyRow(name, row)
	if code == CodeOK {
		if c, is := p["carrier"]; is {
			ss.AddEvent(EvCarrierSwitched, map[string]any{"name": name, "carrier": c, "via": "auto.apply", "row": row})
		}
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// writeTail applies the plan's base_seq rule: a create/edit built on an outdated state_seq still applies
// (Kharej re-validates against its own reality — mismatch is not fatal), but the response carries the fresh
// document so the client can re-decide. The comparison is against the pre-apply seq (captured by the handler
// before the ops ran); base_seq absent or 0 skips the check.
func (ss *ScepterState) writeTail(p map[string]any, req ScepterRequest, pre uint64) map[string]any {
	if base, ok := argInt(req.Args, "base_seq"); ok && base > 0 && uint64(base) != pre {
		p["base_seq"] = base
		p["state"] = ss.document()
	}
	return p
}

// ---- operations (phase D) ----
//
// update.status / update.run / doctor.fetch / backup.export / audit.tail. The engine layer stays thin
// (arg typing, the update bucket, the started event, the base_seq tail); the machinery lives in the ops —
// docs/TECHNICAL.md "Phase D commands: operations" holds the update orchestration contract, the survival
// mechanism and the payload conventions.

// scepterMinScepterVer is the oldest target version update.run may install: below 3.5.0 the peer does not
// serve the scepter stream, so the update would cut the cockpit's only channel to Kharej (re-entry would
// need the local console). Deliberately a constant, not Version: from 3.6.0 on, a 3.5.x recovery downgrade
// must stay possible.
const scepterMinScepterVer = "3.5.0"

// ValidScepterTag validates the update.run `to` argument: a dotted semver with an optional v prefix
// ("3.6.0", "v3.6.0"). The ops re-validate (the ops never trust their caller) and normalize to the tag.
func ValidScepterTag(s string) bool {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// cmdUpdateStatus: update.status — engine version, wattun.prev evidence, unit states and the update mailbox.
// Local reads only: no network fetch from the engine (the cockpit decides what to install, it does not ask
// the engine to go looking).
func cmdUpdateStatus(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	return ss.ops.UpdateStatus()
}

// cmdUpdateRun: update.run {to?} — Kharej runs its own update (plan D.1), the one CapFull-only command.
// The ops stage a verified release and hand the swap to a job that OUTLIVES the engine restart; this handler
// returns a started answer that is journaled (a retried id replays at-most-once, never a second update) and
// flushed long before the job's restart touches the session (the ops' first move after acceptance is a
// several-second grace, and the restart itself waits for the whole download).
func cmdUpdateRun(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	var to string
	if req.Args != nil { // `to` is optional (empty = the latest release); a wrong type is still bad_request
		var ok bool
		if to, ok = argString(req.Args, "to"); !ok {
			return map[string]any{"to": to, "why": "want a dotted version, optionally v-prefixed (v3.6.0)"}, CodeBadRequest
		}
	}
	if to != "" {
		if !ValidScepterTag(to) {
			return map[string]any{"to": to, "why": "want a dotted version, optionally v-prefixed (v3.6.0)"}, CodeBadRequest
		}
		if to == Version || to == strings.TrimPrefix(Version, "v") {
			return map[string]any{"ver": Version, "why": "already running this version"}, CodeBadRequest
		}
		if OlderVersion(strings.TrimPrefix(to, "v"), scepterMinScepterVer) {
			// a pre-Scepter target would come back without the management channel; recovery to a 3.5.x
			// version stays possible on purpose (the cockpit's own rollback tool), 3.4.x does not.
			return map[string]any{"to": to, "why": "below " + scepterMinScepterVer + " the cockpit channel would not come back"}, CodeBadRequest
		}
	}
	if !ss.updateRate.allow(ss.nowf()) {
		return map[string]any{"resource": "update"}, CodeRateLimited
	}
	pre := ss.StateSeq() // see cmdTunnelCreate: base_seq is judged against the pre-apply seq
	p, code := ss.ops.UpdateRun(to)
	if code == CodeOK {
		if run, is := p["run"]; is && p["already_running"] == nil {
			// the watcher owns applied/failed (they can only be known after the revival it reports); the
			// started event is this handler's, so the cockpit sees the intent accepted in-life.
			ss.AddEvent(EvUpdateStarted, map[string]any{"run": run, "to": p["to"]})
		}
		p = ss.writeTail(p, req, pre)
	}
	return p, code
}

// cmdDoctorFetch: doctor.fetch — the structured doctor output. Base document = the state doc (ver, pair,
// tunnels, uptime, event cursor) plus the doctor's last-commands trace (the ONLY user-visible scepter trace,
// plan A.3); the ops merge their fragments (latch status, unit state, update mailbox, journal size) when armed.
func cmdDoctorFetch(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	doc := ss.document()
	doc["recent"] = ss.Recent()
	ss.mu.Lock()
	ops := ss.ops
	ss.mu.Unlock()
	if ops != nil {
		if extra, code := ops.Doctor(); code == CodeOK && extra != nil {
			for k, v := range extra { // the ops fragment adds keys (latch/unit/update/journal); it never clobbers the core doc
				if _, exists := doc[k]; !exists {
					doc[k] = v
				}
			}
		}
	}
	return doc, CodeOK
}

// cmdBackupExport: backup.export — a tarball of the config dir (contents and exclusions documented in the
// ops), delivered through the chunked-logs convention: params {"logs":[doc]} with doc = {b64, sha256, size,
// files}; the serve loop chunks it exactly like tunnel.logs (a tarball has no newlines, so reassembly is the
// identity on the single-element list).
func cmdBackupExport(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	return ss.ops.BackupExport()
}

// cmdAuditTail: audit.tail {n?} — the last n entries of each audit source (the pairing audit written by the
// Kharej console and the scepter command journal), raw lines parse-free (the audit's schema is the manager's;
// re-encoding it here would couple this engine to it). Same chunked-logs convention as backup.export: two
// newline-free JSON docs, one per source.
func cmdAuditTail(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	n, ok := argInt(req.Args, "n")
	if !ok || n < 0 {
		return nil, CodeBadRequest
	}
	if n == 0 {
		n = 100
	}
	n = min(n, 1000)
	return ss.ops.AuditTail(n)
}

// Update-status watcher (phase D). The update job restarts the very engine that ran update.run, so its
// outcome cannot be fired as an event by the process that started it: the job writes every phase transition
// to the .update.status mailbox (atomic tmp+rename) and the REVIVED engine's watcher turns what it observes
// into events — applied/failed/rolled_back for fresh records (1 h window), update_failed {phase:interrupted}
// for a started record that went silent (job died mid-flight: host reboot, systemd-run failure), and nothing
// for older records (history; update.status still serves them). In-life failures (download refused, no
// systemd) never restart anything, so the same watcher catches them too. Cadence cost on the default
// deployment: one failed stat/read of a ~100-byte path every 2 s per paired process.
const (
	scepterUpdatePoll  = 2 * time.Second
	scepterUpdateFresh = time.Hour // a terminal record older than this is history, not news
	// a started record silent this long never finished. It must clear the job's 15 min download cap (the
	// http.Client timeout in cmd/wattun/scepter_ops.go): at 10 min a healthy slow update still in flight
	// fired update_failed {phase:"interrupted"} (round-2 fix 10, 2026-11-22). 20 min clears any download the
	// cap allows and keeps the interrupted verdict prompt for a job that actually died (its watch is ~1 min).
	scepterUpdateStale = 20 * time.Minute
)

func (ss *ScepterState) watchUpdateStatus() {
	path := ss.statusPath()
	if path == "" {
		return
	}
	last := ""
	for {
		time.Sleep(scepterUpdatePoll)
		b, err := os.ReadFile(path)
		if err != nil {
			continue // no update ever run, or the file was cleaned up
		}
		var st ScepterUpdateStatus
		if json.Unmarshal(b, &st) != nil || st.Phase == "" || st.Phase == last {
			continue
		}
		age := ss.nowf().Unix() - st.Ts
		detail := map[string]any{"run": st.Run, "from": st.From, "to": st.To, "phase": st.Phase}
		if st.Detail != "" {
			detail["detail"] = st.Detail
		}
		switch {
		case st.Phase == UpdatePhaseStarted && age > int64(scepterUpdateStale/time.Second):
			detail["phase"] = "interrupted" // the record says started; the event's phase says WHY it is a failure
			ss.AddEvent(EvUpdateFailed, detail)
		case age >= 0 && age < int64(scepterUpdateFresh/time.Second) && st.Phase != UpdatePhaseStarted:
			if st.Phase == UpdatePhaseApplied {
				ss.AddEvent(EvUpdateApplied, detail)
			} else { // failed or rolled_back: both are "the update did not stick"
				ss.AddEvent(EvUpdateFailed, detail)
			}
		}
		last = st.Phase // stale history and fired phases never re-fire; a NEWER record (next update.run) does
	}
}

// ServeScepter runs the server side of one scepter stream: read a line, answer (possibly chunked), repeat until
// the stream ends. The events scepter_up/scepter_down bracket the stream's lifetime for the event log.
func ServeScepter(st *Stream, ss *ScepterState) {
	serveScepterLoop(st, newScepterDecoder(st), ss)
}

// serveScepterLoop is the command loop with a caller-supplied decoder: ServeScepterLatch (latch.go) has already
// consumed the proof line from the same buffer, so it must not build a fresh one.
func serveScepterLoop(st *Stream, d *scepterDecoder, ss *ScepterState) {
	ss.mu.Lock()
	if ss.pair == nil { // disarmed by ReloadPairing(nil) (or a pairing-less state): the reserved stream serves
		// nothing — refused contacts get a reset, never a command answer (F8-revoke, 2026-11-22)
		ss.mu.Unlock()
		st.Reset()
		return
	}
	if ss.lives == nil {
		ss.lives = map[*Stream]struct{}{}
	}
	ss.lives[st] = struct{}{} // registered so ReloadPairing(nil) can kill this stream mid-line
	ss.mu.Unlock()
	defer func() {
		ss.mu.Lock()
		delete(ss.lives, st)
		ss.mu.Unlock()
	}()
	ss.AddEvent(EvScepterUp, nil)
	defer ss.AddEvent(EvScepterDown, nil)
	var wmu sync.Mutex
	for {
		req, code := d.next()
		if code == -1 {
			return
		}
		if code != CodeOK {
			// decode-level garbage is audited too (L4, 2026-11-22): unparseable JSON, a wrong protocol
			// version, an oversized line — a garbage flood leaves a trace in the shared audit file (the
			// audit line sanitizes cmd/id). The PARTIAL request's cmd is used when the line parsed that far
			// (round-2 fix 6, 2026-11-22: a wrong-v line with a valid cmd audited cmd "?"); only a wholly
			// unparseable or oversized line audits the "?" placeholder.
			acmd := req.Cmd
			if acmd == "" {
				acmd = "?"
			}
			uuid, _ := ss.cred()
			ss.audit.record(ss.nowf(), uuid, acmd, req.ID, code)
			writeRespLine(st, &wmu, ScepterResponse{ID: req.ID, Code: code})
			continue
		}
		_, caps := ss.cred() // re-read per command: ReloadPairing (rotate) changes the caps mid-stream
		resp := ss.Handle(req, caps)
		resp.Seq = ss.StateSeq() // the response tail: every answer carries the state it was built on
		writeResp(st, &wmu, resp)
	}
}

// writeResp writes one response, chunking a large params payload (phase A: tunnel.logs) into scepterChunk-byte
// pieces so no single line approaches the 64 KiB command cap from the other side.
func writeResp(st *Stream, wmu *sync.Mutex, resp ScepterResponse) {
	b, err := json.Marshal(resp.Params)
	if err == nil && len(b) > scepterChunk && resp.Code == CodeOK && resp.Params != nil {
		if logs, ok := resp.Params["logs"].([]string); ok && len(logs) > 0 {
			total := strings.Join(logs, "\n")
			n := (len(total) + scepterChunk - 1) / scepterChunk
			if n > 512 { // bounded fan-out: a monster fetch is refused, not exploded
				writeRespLine(st, wmu, ScepterResponse{ID: resp.ID, Code: CodeTooLarge, Seq: resp.Seq})
				return
			}
			for i := 0; i < n; i++ {
				lo := i * scepterChunk
				hi := min(lo+scepterChunk, len(total))
				cr := ScepterResponse{ID: resp.ID, Code: CodeOK, Seq: resp.Seq,
					Chunk: &ScepterChunk{I: i, N: n, Data: total[lo:hi]}}
				writeRespLine(st, wmu, cr)
			}
			return
		}
	}
	writeRespLine(st, wmu, resp)
}

func writeRespLine(st *Stream, wmu *sync.Mutex, resp ScepterResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	wmu.Lock()
	st.Write(append(b, '\n'))
	wmu.Unlock()
}

// ---- client side ----

// ScepterClient speaks the management plane on one open scepter stream.
type ScepterClient struct {
	st    *Stream
	d     *scepterDecoder
	wmu   sync.Mutex
	Hello map[string]any // the server's hello params (ver, caps, uuid, state_seq)
}

// DialScepter opens the reserved stream, runs the pairing hello and returns the client. A peer that answers
// with a version below 3.5.0 (or resets the stream — an old peer without a pairing) fails the dial; the caller
// treats that as "pairing needs 3.5.0 on Kharej" and never retries within the process (mixed-version rule).
func DialScepter(sess *Session) (*ScepterClient, error) {
	if !sess.Paired() {
		return nil, ErrNoPairing
	}
	st, err := sess.OpenScepter()
	if err != nil {
		return nil, err
	}
	c := &ScepterClient{st: st, d: newScepterDecoder(st)}
	if err := c.helloExchange(sess); err != nil {
		return c, err
	}
	return c, nil
}

// scepterPeerVerOK gates the hello on the SCEPTER FLOOR, not the client's own version (M3, 2026-11-22): a
// 3.5.1 client must not refuse a 3.5.0 server's cockpit — the floor (scepterMinScepterVer) is the oldest
// version that serves the management plane at all, which is what "pairing needs" actually means. Empty
// (unparseable) versions still fail closed.
func scepterPeerVerOK(ver string) bool {
	return ver != "" && !OlderVersion(ver, scepterMinScepterVer)
}

// helloExchange runs the pairing hello and version check shared by DialScepter and the latch dial
// (latch.go). On failure the stream is reset and the error says why (mixed-version rule: old peer = no retry).
func (c *ScepterClient) helloExchange(sess *Session) error {
	hello, code := c.call("scepter.hello", map[string]any{"ver": Version, "caps": CapName(sess.cfg.Pairing.Caps)}, "hello", 0, 30*time.Second)
	if code != CodeOK {
		c.st.Reset()
		return fmt.Errorf("scepter: hello rejected (code %d)", code)
	}
	ver, _ := hello["ver"].(string)
	if !scepterPeerVerOK(ver) {
		c.st.Reset()
		return fmt.Errorf("scepter: pairing needs %s on the server, peer reported %q", scepterMinScepterVer, ver)
	}
	c.Hello = hello
	return nil
}

// CloseWrite half-closes; the server's ServeScepter then returns.
func (c *ScepterClient) Close() error { return c.st.CloseWrite() }

// Abort resets the reserved stream: after a transport error the stream state is unknown, and the session allows
// one sid-0 stream at a time, so a broken client must free it before the next DialScepter.
func (c *ScepterClient) Abort() { c.st.Reset() }

// Call runs one command with a fresh id and returns (params, code). Chunked responses are reassembled into
// {"logs": [...]} by splitting the concatenated data on newlines.
func (c *ScepterClient) Call(cmd string, args map[string]any) (map[string]any, int) {
	return c.call(cmd, args, fmt.Sprintf("c%d-%d", time.Now().UnixNano(), scepterCallSeq.Add(1)), time.Now().Unix(), 30*time.Second)
}

// CallRaw runs one command and streams EVERY raw response line for its id (chunk pieces included, in order)
// to w, returning the final response's code — the one-shot `-scepter-call` contract: the caller (the Go
// manager, or any script) parses the JSONL exactly as the protocol speaks it, chunks included. Lines for
// other ids are skipped (the peer may interleave), a transport error or the 30 s deadline ends the stream.
func (c *ScepterClient) CallRaw(cmd string, args map[string]any, id string, w io.Writer) (int, error) {
	if id == "" {
		id = fmt.Sprintf("raw%d-%d", time.Now().UnixNano(), scepterCallSeq.Add(1))
	}
	req := ScepterRequest{ID: id, V: scepterV, Cmd: cmd, Args: args, TS: time.Now().Unix()}
	b, err := json.Marshal(req)
	if err != nil {
		return CodeInternal, err
	}
	c.wmu.Lock()
	_, werr := c.st.Write(append(b, '\n'))
	c.wmu.Unlock()
	if werr != nil {
		return CodeInternal, werr
	}
	deadline := time.Now().Add(30 * time.Second)
	// the stream has no read deadline: a peer that never answers would block ReadSlice forever, so the
	// timeout resets the stream (the caller must re-dial; the session itself is untouched)
	stop := time.AfterFunc(30*time.Second, c.st.Reset)
	defer stop.Stop()
	var nChunks, got int
	for {
		if time.Now().After(deadline) {
			return CodeInternal, errors.New("scepter: response timeout")
		}
		line, err := c.d.br.ReadSlice('\n')
		if err == bufio.ErrBufferFull { // a response line over the cap: drained, reported, never buffered loose
			for {
				if _, e := c.d.br.ReadSlice('\n'); e != bufio.ErrBufferFull {
					break
				}
			}
			return CodeTooLarge, errors.New("scepter: oversized response line")
		}
		if err != nil {
			return CodeInternal, err
		}
		var resp ScepterResponse
		if json.Unmarshal(trimEOL(line), &resp) != nil || resp.ID != id {
			continue
		}
		w.Write(trimEOL(line))
		w.Write([]byte{'\n'})
		if resp.Chunk != nil {
			if nChunks == 0 {
				nChunks = resp.Chunk.N
			}
			got++
			if got < nChunks {
				continue
			}
		}
		return resp.Code, nil
	}
}

// scepterCallSeq disambiguates command ids inside one process (nanoseconds alone can repeat on Windows clocks).
var scepterCallSeq atomic.Uint64

// call is Call with explicit id/ts so retries can reuse them (at-most-once via the server journal).
func (c *ScepterClient) call(cmd string, args map[string]any, id string, ts int64, timeout time.Duration) (map[string]any, int) {
	req := ScepterRequest{ID: id, V: scepterV, Cmd: cmd, Args: args, TS: ts}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, CodeInternal
	}
	c.wmu.Lock()
	if _, err := c.st.Write(append(b, '\n')); err != nil {
		c.wmu.Unlock()
		return nil, CodeInternal
	}
	c.wmu.Unlock()
	return c.waitResp(id, timeout)
}

// waitResp reads until one complete response for id arrives (chunked responses reassembled), skipping
// interleaved lines for other ids. Shared by call and the latch proof ack (latch.go).
func (c *ScepterClient) waitResp(id string, timeout time.Duration) (map[string]any, int) {
	deadline := time.Now().Add(timeout)
	stop := time.AfterFunc(timeout, c.st.Reset) // CallRaw's rule: a silent peer must not block ReadSlice forever
	defer stop.Stop()
	var chunks map[int]string
	var nChunks int
	for {
		if time.Now().After(deadline) {
			return nil, CodeInternal
		}
		line, err := c.d.br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			for {
				if _, e := c.d.br.ReadSlice('\n'); e != bufio.ErrBufferFull {
					break
				}
			}
			return nil, CodeTooLarge
		}
		if err != nil {
			return nil, CodeInternal
		}
		var resp ScepterResponse
		if json.Unmarshal(trimEOL(line), &resp) != nil || resp.ID != id {
			continue // interleaved garbage or a stale answer for another id: skip, keep waiting for ours
		}
		if resp.Chunk != nil {
			if chunks == nil {
				chunks, nChunks = map[int]string{}, resp.Chunk.N
			}
			chunks[resp.Chunk.I] = resp.Chunk.Data
			if len(chunks) < nChunks {
				continue
			}
			var sb strings.Builder
			for i := 0; i < nChunks; i++ {
				sb.WriteString(chunks[i])
			}
			return map[string]any{"logs": strings.Split(sb.String(), "\n")}, resp.Code
		}
		return resp.Params, resp.Code
	}
}

// OlderVersion reports whether a is a dotted version older than b ("3.4.3" < "3.5.0"). Non-parsing a is old
// (fail closed toward "pairing needs an upgrade"). Exported for the phase D update gates: both the engine
// handler (downgrade refusal) and the ops (staged-version sanity) compare dotted versions.
func OlderVersion(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}
