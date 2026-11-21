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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
// parses to (nil, nil) — the token-format rule (optional trailing fields) is preserved.
func ParsePairingTokenField(field10 string, tokenKey []byte) (*PairingConfig, error) {
	if field10 == "" || !strings.HasPrefix(field10, "pair") {
		return nil, nil
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
)

const (
	scepterMaxLine = 64 << 10    // per-command size cap (plan: 64 KB/command)
	scepterChunk   = 16 << 10    // payload bytes per chunked response line (logs)
	scepterV       = 1           // protocol version of this engine
	scepterTTL     = 600         // default intent TTL, seconds (plan: 600)
	scepterSkew    = time.Minute // tolerated client/server clock error for the TTL check
	scepterEvents  = 512         // event ring size (plan: last 512 events replayable)
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
	// are legal up to scepterMaxLine, and a chunked response line is ~scepterChunk + overhead, so both fit with
	// room. A line that fills the buffer WITHOUT a newline is by construction over the cap: drained, rejected.
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
		if err == io.EOF && len(line) == 0 {
			return ScepterRequest{}, -1 // clean end of stream
		}
		return ScepterRequest{}, CodeBadRequest
	}
	if len(line) > scepterMaxLine {
		return ScepterRequest{}, CodeTooLarge
	}
	var req ScepterRequest
	if err := json.Unmarshal(trimEOL(line), &req); err != nil {
		return ScepterRequest{}, CodeBadRequest
	}
	if req.V != scepterV {
		return ScepterRequest{}, CodeBadRequest
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
	EvHealAction      = "heal_action"
	EvSLABreach       = "sla_breach"
	EvUpdateAvailable = "update_available"
	EvPairRotated     = "pair_rotated"
	EvPairRevoked     = "pair_revoked"
	EvScepterUp       = "scepter_up"
	EvScepterDown     = "scepter_down"
)

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

// ScepterJournal is the append-only command journal (plan: every intent with client id, outcome, state_seq;
// rotated at 1 MB; retries of the same command id return the recorded outcome). Records are appended with a
// single O_APPEND write (POSIX-atomic at the sizes involved, ~1 KB) and rotation writes a fresh tmp file that
// atomically replaces the live one — the same discipline as the manager's state files.
type ScepterJournal struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
	keep map[string]ScepterResponse // in-memory replay of live ids (carried across rotation; bounded by use)
}

const scepterJournalRotate = 1 << 20

// journalRec is the on-disk line.
type journalRec struct {
	ID   string          `json:"id"`
	Cmd  string          `json:"cmd"`
	TS   int64           `json:"ts"`
	Resp ScepterResponse `json:"resp"`
}

// OpenScepterJournal loads existing ids (for idempotent retries across a restart) and positions for append.
// A nil path means "no journal" (tests, or pairing without persistence): retries then re-execute.
func OpenScepterJournal(path string) (*ScepterJournal, error) {
	j := &ScepterJournal{path: path, keep: map[string]ScepterResponse{}}
	if path == "" {
		return j, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var r journalRec
			if json.Unmarshal([]byte(line), &r) == nil && r.ID != "" {
				j.keep[r.ID] = r.Resp
			}
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

// Record appends one outcome and remembers it for idempotent retries.
func (j *ScepterJournal) Record(cmd, id string, ts int64, resp ScepterResponse) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if id == "" {
		return // an id-less line (should not happen) is not replayable anyway
	}
	if j.f != nil {
		b, err := json.Marshal(journalRec{ID: id, Cmd: cmd, TS: ts, Resp: resp})
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
	j.keep[id] = resp
}

func (j *ScepterJournal) rotateLocked() {
	j.f.Close()
	tmp := j.path + ".tmp"
	var keep []journalRec
	for id, resp := range j.keep {
		keep = append(keep, journalRec{ID: id, Resp: resp})
	}
	var b strings.Builder
	for _, r := range keep { // short-term idempotency survives rotation; old ids age out (bounded journal)
		if line, err := json.Marshal(r); err == nil {
			b.Write(line)
			b.WriteByte('\n')
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

// Lookup returns the recorded outcome for a command id, if any.
func (j *ScepterJournal) Lookup(id string) (ScepterResponse, bool) {
	if j == nil || id == "" {
		return ScepterResponse{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if r, ok := j.keep[id]; ok {
		return r, true
	}
	return ScepterResponse{}, false
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
// and the rate bucket. One per pairing credential per process; safe for concurrent streams.
type ScepterState struct {
	mu      sync.Mutex
	pair    *PairingConfig
	started time.Time
	seq     uint64
	events  []ScepterEvent // ring: capped at scepterEvents, oldest dropped
	src     ScepterSource
	journal *ScepterJournal
	rate    scepterRate
	recent  []ScepterRec     // last scepterRecent handled commands: the doctor's ONLY visible trace (plan A.3)
	nowf    func() time.Time // tests shrink the clock
}

// ScepterRec is one handled command for the doctor's "last commands" line (Recent).
type ScepterRec struct {
	Cmd  string `json:"cmd"`
	Code int    `json:"code"`
	TS   int64  `json:"ts"`
}

const scepterRecent = 16

// NewScepterState builds the state for a pairing. journalPath may be empty (no journal). src may be nil (the
// tunnel-listing commands answer empty until the binary wires a source).
func NewScepterState(pair *PairingConfig, src ScepterSource, journalPath string) (*ScepterState, error) {
	j, err := OpenScepterJournal(journalPath)
	if err != nil {
		return nil, err
	}
	return &ScepterState{
		pair: pair, src: src, journal: j, started: time.Now(),
		rate: scepterRate{rate: 20, burst: 40},
		nowf: time.Now,
	}, nil
}

// AddEvent records a state change and returns its seq (the state_seq counter increments on EVERY change).
func (ss *ScepterState) AddEvent(kind string, detail map[string]any) uint64 {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.seq++
	ev := ScepterEvent{Seq: ss.seq, Type: kind, TS: ss.nowf().Unix(), Detail: detail}
	ss.events = append(ss.events, ev)
	if len(ss.events) > scepterEvents {
		ss.events = ss.events[len(ss.events)-scepterEvents:]
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
	minCap uint32
	fn     scepterHandler
}

// scepterCmds is the registry. Every entry names its minimum capability and the check runs SERVER-side on every
// command (client-side gating is UX, not security — plan security requirement). Phase A read split: hello/ping
// answer any credential (they reveal only liveness), the pairing's own state (state.get/tunnels.list) answers
// CapTunnel, and everything that reads live telemetry (stats/logs/events/history) needs CapManage per D4
// ("manage: +edit/delete/test/stats/events").
var scepterCmds = map[string]scepterCmd{
	"scepter.hello": {CapTunnel, cmdHello},
	"scepter.ping":  {CapTunnel, cmdPing},
	"state.get":     {CapTunnel, cmdStateGet},
	"tunnels.list":  {CapTunnel, cmdTunnelsList},
	"tunnel.stats":  {CapManage, cmdTunnelStats},
	"tunnel.logs":   {CapManage, cmdTunnelLogs},
	"events.since":  {CapManage, cmdEventsSince},
	"history":       {CapManage, cmdHistory},
}

// Handle validates and runs one request. Order (each step is a trust-boundary check, cheapest first):
// registry → rate → journal replay (idempotency) → TTL → capability → execute → journal. The caller stamps Seq.
func (ss *ScepterState) Handle(req ScepterRequest, caps uint32) ScepterResponse {
	c, ok := scepterCmds[req.Cmd]
	if req.ID == "" || !ok {
		return ScepterResponse{ID: req.ID, Code: CodeUnknownCmd}
	}
	now := ss.nowf()
	ss.mu.Lock()
	rl := ss.rate.allow(now)
	ss.mu.Unlock()
	if !rl {
		return ScepterResponse{ID: req.ID, Code: CodeRateLimited}
	}
	if resp, ok := ss.journal.Lookup(req.ID); ok && resp.ID == req.ID {
		resp.Seq = ss.StateSeq() // refresh the tail: the client may have been offline a while
		return resp
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = scepterTTL
	}
	ts := req.TS
	if ts == 0 {
		ts = now.Unix() // an id-less clock: treat as fresh (the journal still dedups)
	}
	if now.After(time.Unix(ts, 0).Add(time.Duration(ttl)*time.Second + scepterSkew)) {
		return ScepterResponse{ID: req.ID, Code: CodeStale}
	}
	if caps&c.minCap == 0 {
		return ScepterResponse{ID: req.ID, Code: CodeDenied, Params: map[string]any{"need": CapName(c.minCap)}}
	}
	params, code := c.fn(ss, req)
	resp := ScepterResponse{ID: req.ID, Code: code, Params: params}
	if params == nil {
		resp.Params = nil
	}
	if code == CodeOK { // only applied intents are journaled: rejections (denied/stale/rate) are pure functions
		// of the request and safe to recompute on a retry, and journaling them would burn the 1 MB on noise
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
	if ss.pair == nil {
		return "", 0
	}
	return ss.pair.UUIDString(), ss.pair.Caps
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

// cmdHello is the pairing hello exchange (plan phase A item 2): the request's args carry the client's ver/caps
// (informational — the response's own ver is authoritative for the version decision, made by DialScepter).
func cmdHello(ss *ScepterState, req ScepterRequest) (map[string]any, int) {
	return map[string]any{
		"ver": Version, "v": scepterV, "caps": CapName(ss.pair.Caps), "uuid": ss.pair.UUIDString(), "state_seq": ss.StateSeq(),
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

// ServeScepter runs the server side of one scepter stream: read a line, answer (possibly chunked), repeat until
// the stream ends. The events scepter_up/scepter_down bracket the stream's lifetime for the event log.
func ServeScepter(st *Stream, ss *ScepterState) {
	serveScepterLoop(st, newScepterDecoder(st), ss)
}

// serveScepterLoop is the command loop with a caller-supplied decoder: ServeScepterLatch (latch.go) has already
// consumed the proof line from the same buffer, so it must not build a fresh one.
func serveScepterLoop(st *Stream, d *scepterDecoder, ss *ScepterState) {
	caps := uint32(0)
	if ss.pair != nil {
		caps = ss.pair.Caps
	}
	ss.AddEvent(EvScepterUp, nil)
	defer ss.AddEvent(EvScepterDown, nil)
	var wmu sync.Mutex
	for {
		req, code := d.next()
		if code == -1 {
			return
		}
		if code != CodeOK {
			writeRespLine(st, &wmu, ScepterResponse{ID: req.ID, Code: code})
			continue
		}
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

// helloExchange runs the pairing hello and version check shared by DialScepter and the latch dial
// (latch.go). On failure the stream is reset and the error says why (mixed-version rule: old peer = no retry).
func (c *ScepterClient) helloExchange(sess *Session) error {
	hello, code := c.call("scepter.hello", map[string]any{"ver": Version, "caps": CapName(sess.cfg.Pairing.Caps)}, "hello", 0, 30*time.Second)
	if code != CodeOK {
		c.st.Reset()
		return fmt.Errorf("scepter: hello rejected (code %d)", code)
	}
	ver, _ := hello["ver"].(string)
	if ver == "" || olderVersion(ver, Version) {
		c.st.Reset()
		return fmt.Errorf("scepter: pairing needs %s on the server, peer reported %q", Version, ver)
	}
	c.Hello = hello
	return nil
}

// CloseWrite half-closes; the server's ServeScepter then returns.
func (c *ScepterClient) Close() error { return c.st.CloseWrite() }

// Call runs one command with a fresh id and returns (params, code). Chunked responses are reassembled into
// {"logs": [...]} by splitting the concatenated data on newlines.
func (c *ScepterClient) Call(cmd string, args map[string]any) (map[string]any, int) {
	return c.call(cmd, args, fmt.Sprintf("c%d-%d", time.Now().UnixNano(), scepterCallSeq.Add(1)), time.Now().Unix(), 30*time.Second)
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

// olderVersion reports whether a is a dotted version older than b ("3.4.3" < "3.5.0"). Non-parsing a is old
// (fail closed toward "pairing needs an upgrade").
func olderVersion(a, b string) bool {
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
