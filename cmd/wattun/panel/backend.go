package panel

// Backend is everything the panel reads. The binary (cmd/wattun/panel_backend.go) implements it with the manager's
// own functions (cmd/wattun/mgr) and the pairing's scepter commands, so the panel shows exactly what the console
// shows and never parses a config file of its own. Tests use a fake.
type Backend interface {
	Host() Host
	Tunnels() []Tunnel
	Stats(name string) (Counters, bool) // false: no metrics server or not answering
	History(name string) []byte         // the unit's /stats/history JSON (5 min of 5 s samples), nil if none
	Logs(name string, n int) []string   // the unit's journal, newest last
	Kharej() []Kharej                   // one per paired Kharej, through the pairing (may be slow: called by the poller)

	// Actions (phase 2). Each is the console's own function; the panel only asks and shows.
	Unit(name, action string) error // start | stop | restart a tunnel here
	SetPorts(name string, specs []string) error
	SetLimit(name, port, rate, quota, period string) error
	SpeedTest(name, dir string, mb int) (Speed, error)
	Token(name string) string
	// ManagerArgv is the argv of one unattended manager command (`wattun delete NAME --yes` ...): long
	// actions run it as a job, so the panel and the console share one implementation.
	ManagerArgv(args ...string) []string
	// KharejCall runs one pairing command through local tunnel VIA; refused is the console's plain-words
	// refusal ("" = done).
	KharejCall(via, cmd string, args map[string]any) (params map[string]any, refused string, err error)
	KharejCreate(via, name, carrier, ports string) (token string, err error)
	KharejKeyRotate(via, name string) (local, token string, err error)
	KharejBackup(params map[string]any) ([]byte, error)
	RestartSelf() // restart the panel's own unit (after a certificate or port change)
}

// Speed is one direction of the built-in speed test.
type Speed struct {
	Dir     string  `json:"dir"`
	OK      bool    `json:"ok"`
	MBps    float64 `json:"mb_per_s"`
	Seconds float64 `json:"seconds"`
	Error   string  `json:"error,omitempty"`
}

type Host struct {
	Name     string  `json:"name"`
	IP       string  `json:"ip"`
	Version  string  `json:"version"`
	Uptime   int64   `json:"uptime_s"`
	Load1    float64 `json:"load1"`
	CPUs     int     `json:"cpus"`
	MemPct   float64 `json:"mem_pct"`
	DiskPct  float64 `json:"disk_pct"`
	ClockNTP bool    `json:"clock_synced"`
}

type Tunnel struct {
	Name    string   `json:"name"`
	Role    string   `json:"role"` // "Iran" | "Kharej"
	Carrier string   `json:"carrier"`
	Reverse bool     `json:"reverse"`
	Active  bool     `json:"active"`
	Enabled bool     `json:"enabled"` // starts at boot: down while enabled is an outage, stopped by hand is not
	Paired  bool     `json:"paired"`
	Peer    string   `json:"peer,omitempty"`
	Ports   []string `json:"ports"`
	Uptime  string   `json:"uptime,omitempty"`
}

// Counters is the slice of /stats the live view needs. BytesIn/Out are the raw totals; the panel turns them into
// rates. RTT/Loss as reported.
type Counters struct {
	Alive    bool
	RTTms    float64
	LossPct  float64
	BytesIn  float64
	BytesOut float64
	Streams  int64
	Conns    int64
}

type Kharej struct {
	Host    string         `json:"host"`
	Via     []string       `json:"via"` // local tunnels paired with it
	Online  bool           `json:"online"`
	Version string         `json:"version,omitempty"`
	Caps    string         `json:"caps,omitempty"`
	Tunnels []RemoteTunnel `json:"tunnels"`
	Err     string         `json:"error,omitempty"`
	Seen    int64          `json:"seen,omitempty"` // unix seconds of the last good answer
}

type RemoteTunnel struct {
	Name    string `json:"name"`
	Carrier string `json:"carrier"`
	Ports   string `json:"ports,omitempty"`
	State   string `json:"state"`
	Health  string `json:"health"`
}
