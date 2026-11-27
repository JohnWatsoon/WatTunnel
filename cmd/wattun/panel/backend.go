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
	// MovePorts moves mappings from one Iran tunnel to another, opening them on the target's Kharej first (4.0.3).
	MovePorts(from, to string, specs []string) error
	SetLimit(name, port, rate, quota, period string) error
	SpeedTest(name, dir string, mb int) (Speed, error)
	Token(name string) string
	// ManagerArgv is the argv of one unattended manager command (`wattun delete NAME --yes` ...): long
	// actions run it as a job, so the panel and the console share one implementation.
	ManagerArgv(args ...string) []string
	// KharejCall runs one pairing command through local tunnel VIA; refused is the console's plain-words
	// refusal ("" = done).
	KharejCall(via, cmd string, args map[string]any) (params map[string]any, refused string, err error)
	KharejCreate(via, name, carrier, ports, domain string) (token string, err error) // domain: auto only, "" = none
	KharejKeyRotate(via, name string) (local, token string, err error)
	KharejBackup(params map[string]any) ([]byte, error)
	RestartSelf() // restart the panel's own unit (after a certificate or port change)

	Ports(name string) []PortUse // the tunnel's per-port counters, limits and quota usage (its /ports)
	QuotaReset(name string, port int) error
	LatestVersion() string                         // newest release ("" = GitHub not reachable)
	PairRotate(via []string) error                 // new pairing credential from Kharej, attached to every tunnel in VIA
	PairForget(name string) error                  // `pairing: false` on a local tunnel
	PanelFirewall(open, close int)                 // firewall for a panel port change
	Paths(name string) (mode string, paths []Path) // bond mode and live legs of a bonded tunnel
	Geo(addr string) (Geo, error)                  // where an IP or host name is (an outside lookup service; slow, called by a poller)
	Pairing() (token, state string)                // Kharej: the pairing token ("" = not made yet) and who is paired

	// The Settings tab (4.0.1): the console's Advanced rows with presets, start at boot, anti-censorship.
	Settings(name string) any                               // JSON: options, boot, where anti-censorship runs
	ApplySettings(name string, set map[string]string) error // both-ends keys on Kharej first, then here, one restart
	SetBoot(name string, on bool) error
	// Carriers: the last carrier test of an auto Iran tunnel (unix time, preset, ATROW bodies) and the result
	// labels it runs on (4.0.2).
	Carriers(name string) (at int64, preset string, rows, inUse []string)
	ACPreset(name, preset string) (argv []string, err error) // argv: run here as a job; nil: done on Kharej
}

// PortUse is one public port of a tunnel, from its /ports.
type PortUse struct {
	Port       string  `json:"port"`
	Up         float64 `json:"up"`
	Down       float64 `json:"down"`
	RateUp     float64 `json:"rate_up"`
	RateDown   float64 `json:"rate_down"`
	Conns      float64 `json:"conns"`
	RateLimit  float64 `json:"rate_limit"`
	QuotaLimit float64 `json:"quota_limit"`
	QuotaUsed  float64 `json:"quota_used"`
	Exceeded   bool    `json:"exceeded"`
	Period     string  `json:"period,omitempty"`
	ResetsAt   int64   `json:"resets_at,omitempty"`
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
	// CPU use since the previous reading (the panel reads every 10 s; 0 on the first): the whole machine, and
	// every wattun process on it (tunnels, panel, heal) with their memory (4.0.1). -1 = unknown (not Linux).
	CPUPct    float64 `json:"cpu_pct"`
	WatCPUPct float64 `json:"wat_cpu_pct"`
	WatMemMB  float64 `json:"wat_mem_mb"`
	WatProcs  int     `json:"wat_procs"`
	Role      string  `json:"role"` // this server's side: kharej, iran, mixed, "" (not set, no tunnels)
}

// Path is one leg of a bonded tunnel.
type Path struct {
	Name  string `json:"name"`
	Alive bool   `json:"alive"`
	Muted bool   `json:"muted"`
	RTT   string `json:"rtt,omitempty"`
	Loss  string `json:"loss,omitempty"`
	Share string `json:"share,omitempty"`
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
	// Restarts: systemd's automatic restarts of the unit (4.0.1); climbing fast = a crash loop the down alert
	// misses, because the unit is up for a moment between crashes.
	Restarts int `json:"restarts,omitempty"`
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
	PktsOut  float64 // totals since the tunnel started: the live loss is retrans/pkts_out over a window
	Retrans  float64
}

type Kharej struct {
	Host    string         `json:"host"`
	Via     []string       `json:"via"`            // local tunnels paired with it, the pairing link first
	Link    string         `json:"link,omitempty"` // the pairing link to it (Add Kharej); "" = paired by an older tunnel
	Online  bool           `json:"online"`
	Version string         `json:"version,omitempty"`
	Caps    string         `json:"caps,omitempty"`
	Tunnels []RemoteTunnel `json:"tunnels"`
	Err     string         `json:"error,omitempty"`
	Seen    int64          `json:"seen,omitempty"` // unix seconds of the last good answer
	Res     *Host          `json:"res,omitempty"`  // its load, memory, disk, uptime (Kharej 3.6.1+)
}

type RemoteTunnel struct {
	Name    string `json:"name"`
	Carrier string `json:"carrier"`
	Ports   string `json:"ports,omitempty"`
	State   string `json:"state"`
	Health  string `json:"health"`
}
