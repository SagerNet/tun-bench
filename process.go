package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

type processOutput struct {
	access sync.Mutex
	tail   []byte
}

var errProcessPanic = E.New("process panicked")

const processShutdownTimeout = 10 * time.Second

func (o *processOutput) panicError() error {
	for line := range strings.Lines(o.String()) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "panic:") || strings.HasPrefix(line, "fatal error:") || strings.HasPrefix(line, "thread '") && strings.Contains(line, " panicked at ") {
			return E.Extend(errProcessPanic, ": ", line)
		}
	}
	return nil
}

func (o *processOutput) Write(content []byte) (int, error) {
	o.access.Lock()
	defer o.access.Unlock()
	const limit = 1 << 20
	if len(content) >= limit {
		o.tail = append(o.tail[:0], content[len(content)-limit:]...)
	} else {
		if len(o.tail)+len(content) > limit {
			o.tail = o.tail[len(o.tail)+len(content)-limit:]
		}
		o.tail = append(o.tail, content...)
	}
	return len(content), nil
}

func (o *processOutput) String() string {
	o.access.Lock()
	defer o.access.Unlock()
	return string(o.tail)
}

func captureCommandOutput(command *exec.Cmd, stdout, stderr io.Writer, output *processOutput) {
	command.Stdout = output
	if stdout != nil {
		command.Stdout = io.MultiWriter(stdout, output)
	}
	command.Stderr = output
	if stderr != nil {
		command.Stderr = io.MultiWriter(output, stderr)
	}
}

func commandError(command *exec.Cmd, err error, output *processOutput) error {
	if err == nil {
		return nil
	}
	diagnostic := strings.TrimSpace(output.String())
	if diagnostic == "" {
		diagnostic = "process produced no stdout or stderr"
	}
	return E.Cause(E.Errors(err, output.panicError()), "execute ", command.String(), ":\n", diagnostic)
}

func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	var output processOutput
	captureCommandOutput(command, &stdout, &stderr, &output)
	err := command.Run()
	for line := range strings.Lines(stderr.String()) {
		log.Warn(filepath.Base(name), ": ", strings.TrimRight(line, "\r\n"))
	}
	return stdout.Bytes(), commandError(command, E.Errors(ctx.Err(), err), &output)
}

type processOptions struct {
	path            string
	args            []string
	cpus            []int
	env             []string
	stdout          io.Writer
	terminateOnStop bool
}

type process struct {
	command *exec.Cmd
	output  processOutput
	done    chan struct{}
	err     error
	stopErr error
	cancel  context.CancelFunc
	cpus    []int
}

func startProcess(ctx context.Context, options processOptions) (*process, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	command, err := childCommand(context.WithoutCancel(ctx), options.cpus, options.path, options.args)
	if err != nil {
		cancel()
		return nil, E.Cause(err, "prepare ", options.path)
	}
	child := &process{command: command, cancel: cancel, done: make(chan struct{}), cpus: options.cpus}
	command.Env = append(os.Environ(), options.env...)
	captureCommandOutput(command, options.stdout, nil, &child.output)
	command.WaitDelay = 3 * time.Second
	err = command.Start()
	if err != nil {
		cancel()
		return nil, commandError(command, err, &child.output)
	}
	err = setChildAffinity(command.Process.Pid, options.cpus)
	if err != nil {
		killErr := command.Process.Kill()
		waitErr := command.Wait()
		cancel()
		return nil, commandError(command, E.Errors(E.Cause(err, "set affinity"), killErr, waitErr), &child.output)
	}
	go func() {
		waited := make(chan error, 1)
		go func() { waited <- command.Wait() }()
		var waitErr error
		select {
		case waitErr = <-waited:
		case <-ctx.Done():
			select {
			case waitErr = <-waited:
			default:
				stopCtx, stopCancel := context.WithTimeout(context.Background(), processShutdownTimeout)
				var interruptErr error
				var terminated bool
				if options.terminateOnStop {
					interruptErr = command.Process.Kill()
					terminated = interruptErr == nil
				} else {
					interruptErr = interruptProcess(stopCtx, command)
				}
				var reason error
				if interruptErr != nil && !errors.Is(interruptErr, os.ErrProcessDone) {
					reason = E.Cause(interruptErr, "send shutdown signal")
				} else {
					select {
					case waitErr = <-waited:
					case <-stopCtx.Done():
						reason = E.New("process did not stop within ", processShutdownTimeout)
					}
				}
				if reason != nil {
					killErr := command.Process.Kill()
					if !errors.Is(killErr, os.ErrProcessDone) {
						child.stopErr = E.Extend(reason, "; forced termination required")
						child.stopErr = E.Append(child.stopErr, killErr, func(forceErr error) error { return E.Cause(forceErr, "kill process") })
					}
					waitErr = <-waited
				}
				stopCancel()
				var exitErr *exec.ExitError
				if expectedProcessExit(waitErr) || terminated && errors.As(waitErr, &exitErr) && exitErr.ExitCode() == 1 {
					waitErr = nil
				}
				child.stopErr = E.Errors(child.stopErr, waitErr)
			}
		}
		child.err = commandError(command, E.Errors(waitErr, child.stopErr), &child.output)
		if child.stopErr != nil {
			child.stopErr = commandError(command, child.stopErr, &child.output)
		}
		cancel()
		close(child.done)
	}()
	return child, nil
}

func (p *process) stop() error {
	p.cancel()
	<-p.done
	return p.stopErr
}

func (p *process) check() error {
	panicErr := p.output.panicError()
	select {
	case <-p.done:
		if p.err != nil || panicErr != nil {
			return E.Errors(p.err, panicErr)
		}
		return E.New(p.command.Path, " exited unexpectedly: ", p.output.String())
	default:
		return panicErr
	}
}

func (p *process) waitForOutput(ctx context.Context, text string) error {
	return waitUntil(ctx, func() (bool, error) {
		err := p.check()
		if err != nil {
			return false, err
		}
		return strings.Contains(p.output.String(), text), nil
	})
}

func waitUntil(ctx context.Context, ready func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		finished, err := ready()
		if err != nil || finished {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *process) verify() error {
	err := p.check()
	if err != nil {
		return err
	}
	err = verifyAffinity(p.command.Process.Pid, p.cpus)
	if err != nil {
		return E.Cause(err, "verify process placement")
	}
	return nil
}

func verifyProcesses(processes []*process) error {
	for _, child := range processes {
		err := child.verify()
		if err != nil {
			return err
		}
	}
	return nil
}
