//go:build linux || darwin

package main

import (
	"fmt"

	E "github.com/sagernet/sing/common/exceptions"
)

func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)

func x86CPUKind(allowVirtualMachine bool) (string, uint64, error) {
	maximum, vendor, _, _ := cpuid(0, 0)
	signature, _, features, _ := cpuid(1, 0)
	kind := fmt.Sprintf("cpuid:%08x:%08x", vendor, signature)
	if features&(1<<31) != 0 {
		if allowVirtualMachine {
			return "virtual CPU; host scheduling uncontrolled; " + kind, 1, nil
		}
		return "", 0, E.New("a hypervisor hides physical CPU placement; comparable CPU measurements require bare metal")
	}
	const (
		intelVendor = 0x756e6547
		amdVendor   = 0x68747541
	)
	switch vendor {
	case intelVendor:
		if maximum >= 7 {
			_, _, _, features = cpuid(7, 0)
			if features&(1<<15) != 0 {
				if maximum < 0x1a {
					return "", 0, E.New("hybrid Intel CPU does not expose its core type")
				}
				typeID, _, _, _ := cpuid(0x1a, 0)
				return fmt.Sprintf("%s:%08x", kind, typeID), uint64(typeID >> 24), nil
			}
		}
	case amdVendor:
		extended, _, _, _ := cpuid(0x80000000, 0)
		if extended >= 0x80000026 {
			_, topology, _, _ := cpuid(0x80000026, 0)

			kind += fmt.Sprintf(":%02x", topology>>24)
		}
	default:
		return "", 0, E.New("unrecognized x86 CPU vendor: ", fmt.Sprintf("%08x", vendor))
	}
	return kind, 1, nil
}
