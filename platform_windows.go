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
	"strconv"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	getCPUSetInfo      = kernel32.NewProc("GetSystemCpuSetInformation")
	getGroupCount      = kernel32.NewProc("GetActiveProcessorGroupCount")
	getProcessAffinity = kernel32.NewProc("GetProcessAffinityMask")
	setProcessAffinity = kernel32.NewProc("SetProcessAffinityMask")
)

func preparePlatform(_ bool) (environment, error) {
	groups, _, _ := getGroupCount.Call()
	if groups != 1 {
		return environment{}, E.New("CPU measurement currently supports Windows systems with one processor group")
	}
	allowed, err := processAffinity(windows.CurrentProcess())
	if err != nil {
		return environment{}, err
	}
	var size uint32
	_, _, _ = getCPUSetInfo.Call(0, 0, uintptr(unsafe.Pointer(&size)), uintptr(windows.CurrentProcess()), 0)
	if size == 0 {
		return environment{}, E.New("GetSystemCpuSetInformation returned no CPU topology")
	}
	buffer := make([]byte, size)
	succeeded, _, callErr := getCPUSetInfo.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), uintptr(windows.CurrentProcess()), 0)
	if succeeded == 0 {
		return environment{}, callErr
	}
	var cpus []cpuInfo
	for len(buffer) >= 8 {
		length := int(binary.LittleEndian.Uint32(buffer))
		if length < 8 || length > len(buffer) {
			return environment{}, E.New("invalid Windows CPU topology record")
		}
		entry := buffer[:length]
		buffer = buffer[length:]
		if binary.LittleEndian.Uint32(entry[4:]) != 0 {
			continue
		}
		if len(entry) < 32 {
			return environment{}, E.New("truncated Windows CPU set record")
		}
		group := binary.LittleEndian.Uint16(entry[12:])
		id := int(entry[14])
		if group != 0 || allowed&(uintptr(1)<<id) == 0 {
			continue
		}
		flags := entry[19]
		if flags&2 != 0 && flags&4 == 0 {
			continue
		}
		cpus = append(cpus, cpuInfo{
			id: id, core: strconv.Itoa(int(entry[15])),
			kind:     fmt.Sprintf("efficiency=%d,scheduling=%d", entry[18], entry[20]),
			capacity: uint64(entry[18]),
		})
	}
	placement, err := selectCPUs(cpus)
	placement.description = "GetProcessTimes user+kernel time; " + placement.description
	return placement, err
}

func processAffinity(handle windows.Handle) (uintptr, error) {
	var processMask, systemMask uintptr
	succeeded, _, err := getProcessAffinity.Call(uintptr(handle), uintptr(unsafe.Pointer(&processMask)), uintptr(unsafe.Pointer(&systemMask)))
	if succeeded == 0 {
		return 0, err
	}
	return processMask, nil
}

func cpuMask(cpus []int) uintptr {
	var mask uintptr
	for _, cpu := range cpus {
		mask |= uintptr(1) << cpu
	}
	return mask
}

func setChildAffinity(pid int, cpus []int) error {
	handle, err := windows.OpenProcess(windows.PROCESS_SET_INFORMATION|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	succeeded, _, callErr := setProcessAffinity.Call(uintptr(handle), cpuMask(cpus))
	if succeeded == 0 {
		return callErr
	}
	return nil
}

func verifyAffinity(pid int, cpus []int) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	mask, err := processAffinity(handle)
	if err != nil {
		return err
	}
	if mask != cpuMask(cpus) {
		return E.New("process ", pid, " changed CPU affinity")
	}
	return nil
}

func readCounters(pid int) (resourceCounters, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return resourceCounters{}, err
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	err = windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user)
	if err != nil {
		return resourceCounters{}, err
	}

	ticks := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	ticks += uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	return resourceCounters{CPUNanoseconds: ticks * 100}, nil
}

func execChild(_ []string) error {
	return E.New("internal-exec is only used on Linux")
}

func prepareInterface(configuration benchmarkOptions, placement environment, networkInterface *net.Interface) (bool, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(networkInterface.Index))
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	family := winipcfg.AddressFamily(windows.AF_INET)
	if placement.target.Is6() {
		family = windows.AF_INET6
	}
	row, err := luid.IPInterface(family)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// hev-socks5-tunnel uses SetIfEntry, which does not set the IP interface MTU.
	if configuration.software == "hev-socks5-tunnel" && row.NLMTU != uint32(configuration.MTU) {
		row.NLMTU = uint32(configuration.MTU)
		err = row.Set()
		return false, err
	}
	if !row.Connected || row.NLMTU != uint32(configuration.MTU) {
		return false, nil
	}
	address, err := luid.IPAddress(placement.address.Addr())
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if address.DadState == winipcfg.DadStateDuplicate {
		return false, E.New("duplicate TUN address: ", placement.address.Addr())
	}
	return address.DadState == winipcfg.DadStatePreferred, nil
}

func configureInterface(_ context.Context, configuration benchmarkOptions, placement environment, networkInterface *net.Interface) (configured bool, returnErr error) {
	defer func() {
		if errors.Is(returnErr, windows.ERROR_NOT_FOUND) {
			configured, returnErr = false, nil
		}
	}()
	luid, err := winipcfg.LUIDFromIndex(uint32(networkInterface.Index))
	if err != nil {
		return false, err
	}
	err = luid.AddIPAddress(placement.address)
	if err != nil && err != windows.ERROR_OBJECT_ALREADY_EXISTS {
		return false, err
	}
	family := winipcfg.AddressFamily(windows.AF_INET)
	if placement.address.Addr().Is6() {
		family = windows.AF_INET6
	}
	row, err := luid.IPInterface(family)
	if err != nil {
		return false, err
	}
	row.NLMTU = uint32(configuration.MTU)
	err = row.Set()
	return err == nil, err
}

func routePrefixes(_ context.Context) ([]netip.Prefix, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return common.Map(routes, func(route winipcfg.MibIPforwardRow2) netip.Prefix { return route.DestinationPrefix.Prefix() }), nil
}

func updateRoute(_ context.Context, placement environment, interfaceIndex int, operation string) error {
	luid, err := winipcfg.LUIDFromIndex(uint32(interfaceIndex))
	if err != nil {
		return err
	}
	destination := netip.PrefixFrom(placement.target, placement.target.BitLen())
	nextHop := netip.IPv4Unspecified()
	if placement.target.Is6() {
		nextHop = netip.IPv6Unspecified()
	}
	if operation == "add" {
		return luid.AddRoute(destination, nextHop, 0)
	}
	return luid.DeleteRoute(destination, nextHop)
}

const memoryMetric = "working_set"

var getProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")

type processMemoryCounters struct {
	Size                       uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func readMemory(pid int) (uint64, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	var info processMemoryCounters
	info.Size = uint32(unsafe.Sizeof(info))
	succeeded, _, callErr := getProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&info)), uintptr(info.Size))
	if succeeded == 0 {
		return 0, callErr
	}
	return uint64(info.WorkingSetSize), nil
}

func prepareMemoryLimit() error { return nil }

func childCommand(ctx context.Context, _ []int, path string, args []string) (*exec.Cmd, error) {
	enabled, _, enableErr := kernel32.NewProc("SetConsoleCtrlHandler").Call(0, 0)
	if enabled == 0 {
		return nil, E.Cause(enableErr, "enable child Ctrl+C inheritance")
	}
	command := exec.CommandContext(ctx, path, args...)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
	return command, nil
}

func interruptProcess(ctx context.Context, child *exec.Cmd) error {
	signalExecutable := filepath.Join(filepath.Dir(child.Path), "msys-kill.exe")
	_, err := os.Stat(signalExecutable)
	var command *exec.Cmd
	if err == nil {
		command = exec.CommandContext(ctx, signalExecutable, "--signal", "TERM", "--winpid", strconv.Itoa(child.Process.Pid))
	} else if errors.Is(err, os.ErrNotExist) {
		var self string
		self, err = os.Executable()
		if err != nil {
			return err
		}
		command = exec.CommandContext(ctx, self, "internal-interrupt", strconv.Itoa(child.Process.Pid))
	} else {
		return err
	}
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	command.WaitDelay = processShutdownTimeout
	var output processOutput
	captureCommandOutput(command, nil, nil, &output)
	err = command.Run()
	return commandError(command, err, &output)
}

func execInterrupt(value string) error {
	processID := common.Must1(strconv.ParseUint(value, 10, 32))
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(processID))
	if err != nil {
		if err == windows.ERROR_INVALID_PARAMETER {
			return nil
		}
		return err
	}
	defer windows.CloseHandle(handle)
	_, _, _ = kernel32.NewProc("FreeConsole").Call()
	attached, _, attachErr := kernel32.NewProc("AttachConsole").Call(uintptr(processID))
	if attached == 0 {
		state, waitErr := windows.WaitForSingleObject(handle, 0)
		if waitErr == nil && state == windows.WAIT_OBJECT_0 {
			return nil
		}
		return E.Cause(attachErr, "attach child console")
	}
	ignored, _, ignoreErr := kernel32.NewProc("SetConsoleCtrlHandler").Call(0, 1)
	if ignored == 0 {
		return E.Cause(ignoreErr, "ignore helper Ctrl+C")
	}
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0)
}

func expectedProcessExit(err error) bool {
	return err == nil
}

func validateCacheDirectory(directory string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return E.New("cache must be a directory")
	}
	security, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := security.Owner()
	if err != nil {
		return err
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if owner.Equals(currentUser.User.Sid) {
		return nil
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		var member bool
		member, err = windows.Token(0).IsMember(owner)
		if err != nil {
			return err
		}
		if member {
			return nil
		}
	}
	return E.New("cache must be owned by the current user")
}

func openResult(path string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func replaceResult(source, destination string) error {
	sourcePointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(sourcePointer, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: source, Err: err}
	}
	defer windows.CloseHandle(handle)
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(absolute)
	if err != nil {
		return err
	}
	type renameInformation struct {
		Flags         uint32
		RootDirectory windows.Handle
		NameLength    uint32
		Name          [1]uint16
	}
	var layout renameInformation
	nameLength := len(name) - 1
	buffer := make([]byte, int(unsafe.Offsetof(layout.Name))+nameLength*2)
	information := (*renameInformation)(unsafe.Pointer(&buffer[0]))
	information.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	information.NameLength = uint32(nameLength * 2)
	copy(unsafe.Slice(&information.Name[0], nameLength), name[:nameLength])
	err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return &os.LinkError{Op: "rename", Old: source, New: destination, Err: err}
	}
	return nil
}
