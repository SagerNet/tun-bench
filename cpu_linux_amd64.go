package main

import (
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func architectureCPUKind(cpu int, allowVirtualMachine bool) (string, uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var original, selected unix.CPUSet
	err := unix.SchedGetaffinity(0, &original)
	if err != nil {
		return "", 0, err
	}
	selected.Set(cpu)
	err = unix.SchedSetaffinity(0, &selected)
	if err != nil {
		return "", 0, err
	}
	kind, capacity, err := x86CPUKind(allowVirtualMachine)
	err = E.Append(err, unix.SchedSetaffinity(0, &original), func(restoreErr error) error {
		return E.Cause(restoreErr, "restore CPU affinity")
	})
	return kind, capacity, err
}
