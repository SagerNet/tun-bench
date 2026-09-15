package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

var errHybridDarwin = E.New("macOS cannot bind processes to one class of a heterogeneous CPU")

type rusageInfo struct {
	UUID              [16]byte
	UserTime          uint64
	SystemTime        uint64
	Unused            [5]uint64
	PhysicalFootprint uint64
	BeforeEnergy      [32]uint64
	EnergyNanojoules  uint64
	Remaining         [15]uint64
}

type rusageFunc func(pid int32, flavor int32, info *rusageInfo) int32

var loadRusage = sync.OnceValues(func() (rusageFunc, error) {
	library, err := purego.Dlopen("/usr/lib/libproc.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	address, err := purego.Dlsym(library, "proc_pid_rusage")
	if err != nil {
		_ = purego.Dlclose(library)
		return nil, err
	}
	var call rusageFunc
	purego.RegisterFunc(&call, address)
	return call, nil
})

func readRusage(pid int, flavor int32) (rusageInfo, error) {
	var info rusageInfo
	call, err := loadRusage()
	if err != nil {
		return info, err
	}
	code := call(int32(pid), flavor, &info)
	if code != 0 {
		return info, E.New("proc_pid_rusage(", pid, ", V", flavor, ") returned ", code)
	}
	return info, nil
}

func preparePlatform(allowVirtualMachine bool) (environment, error) {
	placement := environment{workers: runtime.NumCPU(), helpers: runtime.NumCPU()}
	info, err := readRusage(os.Getpid(), 6)
	if err == nil && info.EnergyNanojoules > 0 {
		placement.metric = metricEnergy
		placement.description = "proc_pid_rusage RUSAGE_INFO_V6 CPU energy (J); includes execution on all core types"
		return placement, nil
	}
	kind, err := homogeneousDarwinCPU(allowVirtualMachine)
	if err != nil {
		return placement, E.Cause(err, "no usable process energy counter, and CPU time is not comparable")
	}
	_, err = readRusage(os.Getpid(), 0)
	if err != nil {
		return placement, err
	}
	placement.metric = metricCPU
	placement.description = "proc_pid_rusage user+system time; " + kind + "; macOS scheduler placement"
	return placement, nil
}

func readCounters(pid int) (resourceCounters, error) {
	info, err := readRusage(pid, 6)
	if err != nil {
		info, err = readRusage(pid, 0)
		if err != nil {
			return resourceCounters{}, err
		}
	}

	frequency, err := machTimebaseFrequency()
	if err != nil {
		return resourceCounters{}, err
	}

	ticks := info.UserTime + info.SystemTime
	return resourceCounters{
		CPUNanoseconds:   ticks/frequency*1e9 + ticks%frequency*1e9/frequency,
		EnergyNanojoules: info.EnergyNanojoules,
	}, nil
}

func childCommand(ctx context.Context, _ []int, path string, args []string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, path, args...), nil
}

func execChild(_ []string) error {
	return E.New("internal-exec is only used on Linux")
}

func setChildAffinity(_ int, _ []int) error { return nil }
func verifyAffinity(_ int, _ []int) error   { return nil }

func prepareInterface(configuration benchmarkOptions, _ environment, networkInterface *net.Interface) (bool, error) {
	return networkInterface.MTU == configuration.MTU, nil
}

var machTimebaseFrequency = sync.OnceValues(func() (uint64, error) {
	data, err := unix.SysctlRaw("hw.tbfrequency")
	if err != nil {
		return 0, err
	}
	var frequency uint64
	switch len(data) {
	case 4:
		frequency = uint64(binary.NativeEndian.Uint32(data))
	case 8:
		frequency = binary.NativeEndian.Uint64(data)
	}
	if frequency == 0 {
		return 0, E.New("invalid Mach timebase frequency")
	}
	return frequency, nil
})

func configureInterface(ctx context.Context, configuration benchmarkOptions, placement environment, networkInterface *net.Interface) (bool, error) {
	args := []string{networkInterface.Name, "inet", placement.address.Addr().String(), placement.address.Addr().Next().String(), "alias"}
	if placement.address.Addr().Is6() {
		args = []string{networkInterface.Name, "inet6", placement.address.String(), "alias", "-dad"}
	}
	args = append(args, "mtu", strconv.Itoa(configuration.MTU), "up")
	err := runCommand(ctx, "/sbin/ifconfig", args...)
	return err == nil, err
}

func routePrefixes(ctx context.Context) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, family := range []string{"inet", "inet6"} {
		data, err := commandOutput(ctx, "/usr/sbin/netstat", "-rn", "-f", family)
		if err != nil {
			return nil, err
		}
		inTable := false
		for line := range strings.Lines(string(data)) {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if fields[0] == "Destination" {
				inTable = true
				continue
			}
			if !inTable {
				continue
			}
			prefix, parseErr := parseRoutePrefix(fields[0])
			if parseErr != nil {
				return nil, parseErr
			}
			if prefix.IsValid() {
				prefixes = append(prefixes, prefix)
			}
		}
	}
	return prefixes, nil
}

func updateRoute(ctx context.Context, placement environment, interfaceIndex int, operation string) error {
	family := "-inet"
	if placement.target.Is6() {
		family = "-inet6"
	}
	return runCommand(ctx, "/sbin/route", "-n", operation, family, "-host", placement.target.String(), "-interface", placement.interfaceName)
}

const memoryMetric = "physical_footprint"

func readMemory(pid int) (uint64, error) {
	info, err := readRusage(pid, 0)
	return info.PhysicalFootprint, err
}
