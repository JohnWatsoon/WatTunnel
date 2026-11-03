package wat

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
)

func TestHardwareProfile(t *testing.T) {
	hp := HostProfile()
	if hp.TotalRAMMB < 0 {
		t.Fatalf("invalid TotalRAMMB: %d", hp.TotalRAMMB)
	}
	want := profileForResources(min(runtime.NumCPU(), runtime.GOMAXPROCS(0)), hp.TotalRAMMB)
	if hp != want {
		t.Fatalf("HostProfile() = %+v, want %+v", hp, want)
	}
}

func TestHardwareProfileParallelism(t *testing.T) {
	for _, cpus := range []int{1, runtime.NumCPU() + 1} {
		t.Run(strconv.Itoa(cpus), func(t *testing.T) {
			// HostProfile is already cached by package initialization, so use a fresh process.
			cmd := exec.Command(os.Args[0], "-test.run=^TestHardwareProfile$")
			cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(cpus))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("GOMAXPROCS=%d: %v\n%s", cpus, err, out)
			}
		})
	}
}

func TestProfileForResources(t *testing.T) {
	lean := HardwareProfile{
		Tier: TierLean, DefaultPoolConns: 8, DefaultSessions: 1,
		WinCap: 4 << 20, MaxSessionWin: 32 << 20, PoolLowat: 64 << 10,
	}
	standard := HardwareProfile{
		Tier: TierStandard, DefaultPoolConns: 16, DefaultSessions: 2,
		WinCap: 16 << 20, MaxSessionWin: 64 << 20, PoolLowat: 128 << 10,
	}
	high := HardwareProfile{
		Tier: TierHighPerf, DefaultPoolConns: 24, DefaultSessions: 2,
		WinCap: 32 << 20, MaxSessionWin: 128 << 20, PoolLowat: 256 << 10,
	}
	high4 := high
	high4.DefaultPoolConns, high4.DefaultSessions = 32, 2

	for _, tc := range []struct {
		name               string
		cpus, ram, wantCPU int
		want               HardwareProfile
	}{
		{"unknown RAM", 4, 0, 4, lean},
		{"negative RAM", 4, -1, 4, lean},
		{"tiny RAM", 4, 1, 4, lean},
		{"low memory overrides CPUs", 8, 1024, 8, lean},
		{"below lean boundary", 2, 1535, 2, lean},
		{"at lean boundary", 4, 1536, 4, lean},
		{"above lean boundary", 2, 1537, 2, standard},
		{"standard four CPUs", 4, 2048, 4, standard},
		{"below high boundary", 2, 3499, 2, standard},
		{"at high boundary", 2, 3500, 2, high},
		{"above high boundary", 2, 3501, 2, high},
		{"high three CPUs", 3, 8192, 3, high},
		{"high four CPUs", 4, 8192, 4, high4},
		{"high eight CPUs", 8, 8192, 8, high4},
		{"one CPU standard memory", 1, 2048, 1, lean},
		{"one CPU high memory", 1, 8192, 1, lean},
		{"zero CPUs", 0, 8192, 1, lean},
		{"negative CPUs", -1, 8192, 1, lean},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			want.NumCPU, want.TotalRAMMB = tc.wantCPU, max(0, tc.ram)
			if got := profileForResources(tc.cpus, tc.ram); got != want {
				t.Fatalf("profileForResources(%d, %d) = %+v, want %+v", tc.cpus, tc.ram, got, want)
			}
		})
	}
}
