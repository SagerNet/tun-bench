package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var processTestHelpers = map[string]func(){"process-test-helper": processTestHelper}

func TestMain(tests *testing.M) {
	if len(os.Args) > 1 {
		helper, loaded := processTestHelpers[os.Args[1]]
		if loaded {
			helper()
			return
		}
		if strings.HasPrefix(os.Args[1], "internal-") {
			main()
			return
		}
	}
	os.Exit(tests.Run())
}

func processTestHelper() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("ready", listener.Addr())
	select {
	case <-signals:
	case <-time.After(30 * time.Second):
		panic("test helper did not receive shutdown signal")
	}
	fmt.Println("shutdown signal received")
	switch os.Args[2] {
	case "ignore":
		time.Sleep(30 * time.Second)
		panic("test helper was not killed")
	case "panic":
		panic("failure during shutdown")
	}
	err = os.WriteFile(os.Args[3], []byte("closed"), 0o600)
	if err != nil {
		panic(err)
	}
}

func startTestProcess(t *testing.T, args ...string) *process {
	t.Helper()
	placement, err := preparePlatform(true)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	child, err := startProcess(ctx, processOptions{path: self, args: args, cpus: placement.cpus})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.stop() })
	err = child.waitForOutput(ctx, "ready ")
	if err != nil {
		t.Fatal(err)
	}
	return child
}

func TestProcessGracefulShutdown(t *testing.T) {
	t.Parallel()
	marker := filepath.Join(t.TempDir(), "closed")
	child := startTestProcess(t, "process-test-helper", "graceful", marker)
	siblingMarker := filepath.Join(t.TempDir(), "closed")
	sibling := startTestProcess(t, "process-test-helper", "graceful", siblingMarker)
	var address string
	_, err := fmt.Sscanf(child.output.String(), "ready %s", &address)
	if err != nil {
		t.Fatal(err)
	}
	err = child.stop()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(marker)
	if err != nil {
		t.Fatal("child did not finish its shutdown handler: ", err)
	}
	connection, dialErr := net.DialTimeout("tcp", address, time.Second)
	if dialErr == nil {
		connection.Close()
		t.Fatal("child listener survived shutdown")
	}
	err = sibling.check()
	if err != nil {
		t.Fatal("stopping one child stopped its sibling: ", err)
	}
	err = sibling.stop()
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(siblingMarker)
	if err != nil {
		t.Fatal("sibling did not finish its shutdown handler: ", err)
	}
}

func TestProcessForcedShutdown(t *testing.T) {
	t.Parallel()
	marker := filepath.Join(t.TempDir(), "closed")
	child := startTestProcess(t, "process-test-helper", "ignore", marker)
	err := child.stop()
	if err == nil || !strings.Contains(err.Error(), "forced termination required") {
		t.Fatal("forced termination was not reported: ", err)
	}
	if !strings.Contains(child.output.String(), "shutdown signal received") {
		t.Fatal("unresponsive child never received the shutdown signal")
	}
	if child.command.ProcessState == nil || child.command.ProcessState.Success() {
		t.Fatal("unresponsive child was not terminated")
	}
	_, err = os.Stat(marker)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unresponsive child ran its cleanup: ", err)
	}
}

func TestProcessShutdownPanic(t *testing.T) {
	t.Parallel()
	child := startTestProcess(t, "process-test-helper", "panic", filepath.Join(t.TempDir(), "closed"))
	err := child.stop()
	if !errors.Is(err, errProcessPanic) {
		t.Fatal("shutdown panic was lost: ", err)
	}
}
