package wat

import (
	"runtime"
	"sync"
)

type HardwareTier string

const (
	TierLean     HardwareTier = "lean"
	TierStandard HardwareTier = "standard"
	TierHighPerf HardwareTier = "highperf"
)

type HardwareProfile struct {
	NumCPU           int
	TotalRAMMB       int
	Tier             HardwareTier
	DefaultPoolConns int
	DefaultSessions  int
	WinCap           uint64
	MaxSessionWin    uint64
	PoolLowat        int
}

var (
	hostProfileOnce sync.Once
	hostProfile     HardwareProfile
)

// HostProfile caches startup resources; Go parallelism may round up CPU quotas.
func HostProfile() HardwareProfile {
	hostProfileOnce.Do(func() {
		cpus := min(runtime.NumCPU(), runtime.GOMAXPROCS(0))
		hostProfile = profileForResources(cpus, totalSystemRAMMB())
	})
	return hostProfile
}

func profileForResources(cpus, ram int) HardwareProfile {
	cpus = max(1, cpus)
	ram = max(0, ram)
	tier := TierStandard
	if ram <= 1536 || cpus <= 1 {
		tier = TierLean
	} else if ram >= 3500 && cpus >= 2 {
		tier = TierHighPerf
	}

	conns := 8
	sessions := 1
	winCap := uint64(16 << 20)
	maxSessWin := uint64(64 << 20)
	lowat := 128 << 10

	switch tier {
	case TierLean:
		conns = 8
		sessions = 1
		winCap = 4 << 20 // Pin to the base window to bound per-stream buffering.
		maxSessWin = 32 << 20
		lowat = 64 << 10
	case TierStandard:
		conns = 16
		if cpus >= 2 {
			sessions = 2
		}
		winCap = 16 << 20
		maxSessWin = 64 << 20
		lowat = 128 << 10
	case TierHighPerf:
		conns = 24
		if cpus >= 4 {
			conns = 32
		}
		sessions = 2 // 4 sessions on one pair: 147 MB/s, 2 sessions: 261 (their pacers read each other's queue, 3.2.0)
		winCap = 32 << 20
		maxSessWin = 128 << 20
		lowat = 256 << 10
	}

	return HardwareProfile{
		NumCPU:           cpus,
		TotalRAMMB:       ram,
		Tier:             tier,
		DefaultPoolConns: conns,
		DefaultSessions:  sessions,
		WinCap:           winCap,
		MaxSessionWin:    maxSessWin,
		PoolLowat:        lowat,
	}
}
