package main

import "golang.org/x/sys/unix"

func homogeneousDarwinCPU(_ bool) (string, error) {
	levels, err := unix.SysctlUint32("hw.nperflevels")
	if err != nil {
		return "", err
	}
	if levels != 1 {
		return "", errHybridDarwin
	}
	return "homogeneous CPU", nil
}
