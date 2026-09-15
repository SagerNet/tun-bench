//go:build linux && !amd64

package main

func architectureCPUKind(_ int, _ bool) (string, uint64, error) { return "", 0, nil }
