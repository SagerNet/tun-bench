package main

func homogeneousDarwinCPU(allowVirtualMachine bool) (string, error) {
	kind, _, err := x86CPUKind(allowVirtualMachine)
	if err != nil {
		return "", err
	}
	_, _, _, features := cpuid(7, 0)
	if features&(1<<15) != 0 {
		return "", errHybridDarwin
	}
	return kind, nil
}
