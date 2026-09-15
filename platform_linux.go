package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"

	"golang.org/x/sys/unix"
)

func preparePlatform(allowVirtualMachine bool) (environment, error) {
	var allowed unix.CPUSet
	err := unix.SchedGetaffinity(0, &allowed)
	if err != nil {
		return environment{}, err
	}
	var cpus []cpuInfo
	for cpu := range 1024 {
		if !allowed.IsSet(cpu) {
			continue
		}
		info, infoErr := linuxCPUInfo(cpu, allowVirtualMachine)
		if infoErr != nil {
			return environment{}, infoErr
		}
		cpus = append(cpus, info)
	}
	placement, err := selectCPUs(cpus)
	placement.description = "/proc/PID/stat user+system time; " + placement.description
	return placement, err
}

func linuxCPUInfo(cpu int, allowVirtualMachine bool) (cpuInfo, error) {
	info := cpuInfo{id: cpu}
	base := fmt.Sprintf("/sys/devices/system/cpu/cpu%d", cpu)
	core, err := os.ReadFile(filepath.Join(base, "topology/thread_siblings_list"))
	if err != nil {
		return info, err
	}
	info.core = strings.TrimSpace(string(core))
	info.kind, info.capacity, err = architectureCPUKind(cpu, allowVirtualMachine)
	if err != nil {
		return info, err
	}
	for _, field := range []string{"cpu_capacity", "topology/core_type", "regs/identification/midr_el1"} {
		value, readErr := os.ReadFile(filepath.Join(base, field))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return info, readErr
		}
		text := strings.TrimSpace(string(value))
		if text == "" || text == "0" {
			continue
		}
		info.kind += ";" + field + "=" + text
		if field == "cpu_capacity" {
			info.capacity, err = strconv.ParseUint(text, 10, 64)
			if err != nil {
				return info, err
			}
		}
	}
	if info.kind == "" {
		return info, E.New("CPU ", cpu, " has no usable core classification")
	}
	return info, nil
}

func execChild(args []string) error {
	var set unix.CPUSet
	for item := range strings.SplitSeq(args[0], ",") {
		set.Set(common.Must1(strconv.Atoi(item)))
	}
	runtime.LockOSThread()
	err := unix.SchedSetaffinity(0, &set)
	if err != nil {
		return err
	}
	return syscall.Exec(args[1], args[1:], os.Environ())
}

func childCommand(ctx context.Context, cpus []int, path string, args []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, self, append([]string{"internal-exec", strings.Join(F.MapToString(cpus), ","), path}, args...)...), nil
}

func setChildAffinity(pid int, cpus []int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var placementErr error
	err := waitUntil(ctx, func() (bool, error) {
		placementErr = verifyAffinity(pid, cpus)
		if errors.Is(placementErr, unix.ESRCH) || errors.Is(placementErr, os.ErrNotExist) {
			return false, placementErr
		}
		return placementErr == nil, nil
	})
	return E.Errors(err, placementErr)
}

func verifyAffinity(pid int, cpus []int) error {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		threadID, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil {
			return parseErr
		}
		var actual unix.CPUSet
		err = unix.SchedGetaffinity(threadID, &actual)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return err
		}
		if actual.Count() != len(cpus) {
			return E.New("process ", pid, " thread ", threadID, " changed CPU affinity")
		}
		for _, cpu := range cpus {
			if !actual.IsSet(cpu) {
				return E.New("process ", pid, " thread ", threadID, " escaped CPU affinity")
			}
		}
	}
	return nil
}

var clockTicks = sync.OnceValues(func() (uint64, error) {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}
	width := strconv.IntSize / 8
	word := func(content []byte) uint64 {
		if width == 8 {
			return binary.NativeEndian.Uint64(content)
		}
		return uint64(binary.NativeEndian.Uint32(content))
	}
	for len(data) >= width*2 {
		if word(data) == 17 {
			ticks := word(data[width:])
			if ticks > 0 {
				return ticks, nil
			}
		}
		data = data[width*2:]
	}
	return 0, E.New("AT_CLKTCK is unavailable")
})

func readCounters(pid int) (resourceCounters, error) {
	ticks, err := clockTicks()
	if err != nil {
		return resourceCounters{}, err
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return resourceCounters{}, err
	}
	content := string(data)
	end := strings.LastIndexByte(content, ')')
	if end < 0 {
		return resourceCounters{}, E.New("invalid process stat")
	}
	fields := strings.Fields(content[end+1:])
	if len(fields) < 13 {
		return resourceCounters{}, E.New("truncated process stat")
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return resourceCounters{}, err
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return resourceCounters{}, err
	}
	total := user + system
	return resourceCounters{CPUNanoseconds: total/ticks*1e9 + total%ticks*1e9/ticks}, nil
}

func prepareInterface(configuration benchmarkOptions, placement environment, networkInterface *net.Interface) (bool, error) {
	if networkInterface.MTU != configuration.MTU {
		return false, nil
	}
	queues, err := filepath.Glob(filepath.Join("/sys/class/net", placement.interfaceName, "queues/tx-*"))
	return len(queues) == configuration.queues, err
}

func configureInterface(ctx context.Context, configuration benchmarkOptions, placement environment, networkInterface *net.Interface) (bool, error) {
	args := []string{"address", "replace", placement.address.String(), "dev", networkInterface.Name}
	if placement.address.Addr().Is6() {
		args = append(args, "nodad")
	}
	err := runCommand(ctx, "ip", args...)
	if err != nil {
		return false, err
	}
	err = runCommand(ctx, "ip", "link", "set", "dev", networkInterface.Name, "mtu", strconv.Itoa(configuration.MTU), "up")
	return err == nil, err
}

func routePrefixes(ctx context.Context) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, family := range []string{"-4", "-6"} {
		data, err := commandOutput(ctx, "ip", family, "-json", "route", "show", "table", "all")
		if err != nil {
			return nil, err
		}
		var routes []struct {
			Destination string `json:"dst"`
		}
		err = json.Unmarshal(data, &routes)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			prefix, parseErr := parseRoutePrefix(route.Destination)
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
	family := "-4"
	if placement.target.Is6() {
		family = "-6"
	}
	return runCommand(ctx, "ip", family, "route", operation, netip.PrefixFrom(placement.target, placement.target.BitLen()).String(), "dev", placement.interfaceName)
}

const memoryMetric = "rss"

func readMemory(pid int) (uint64, error) {
	prefix := "/proc/" + strconv.Itoa(pid) + "/"
	content, err := os.ReadFile(prefix + "smaps_rollup")
	if errors.Is(err, os.ErrNotExist) {
		content, err = os.ReadFile(prefix + "smaps")
	}
	if err != nil {
		return 0, err
	}
	var total uint64
	found := false
	for line := range strings.SplitSeq(string(content), "\n") {
		if !strings.HasPrefix(line, "Rss:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, E.New("invalid process RSS")
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return 0, parseErr
		}
		total += value * 1024
		found = true
	}
	if !found {
		return 0, E.New("process RSS is unavailable")
	}
	return total, nil
}
