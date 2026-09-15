package main

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type workerRequest struct {
	AllowVirtualMachine bool             `json:"allow_virtual_machine,omitempty"`
	Environment         string           `json:"environment"`
	Local               bool             `json:"local,omitempty"`
	OS                  string           `json:"os"`
	Arch                string           `json:"arch"`
	FailFast            bool             `json:"fail_fast"`
	Cases               []workerCase     `json:"cases"`
	Report              *benchmarkReport `json:"report,omitempty"`
}

type workerCase struct {
	Case       caseConfiguration `json:"case"`
	Software   string            `json:"software"`
	Executable string            `json:"executable"`
	Package    string            `json:"package,omitempty"`
	Version    string            `json:"version,omitempty"`
	Iperf      string            `json:"iperf3"`
	IperfArch  string            `json:"iperf3_arch,omitempty"`
	Relay      string            `json:"relay,omitempty"`
}

type workerUpdate struct {
	Report  *benchmarkReport `json:"report"`
	Started *caseResult      `json:"started,omitempty"`
}

func writeWorkerBundle(destination string, cases []benchmarkOptions, target environmentConfiguration, report *benchmarkReport, failFast bool) (returnErr error) {
	file, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer func() { returnErr = E.Errors(returnErr, file.Close()) }()
	archive := tar.NewWriter(file)
	defer func() { returnErr = E.Errors(returnErr, archive.Close()) }()
	request := workerRequest{Environment: cases[0].environmentName, Local: target.Type == "local", OS: target.OS, Arch: target.Arch, Report: report, FailFast: failFast, AllowVirtualMachine: target.AllowVirtualMachine}
	paths := make(map[string]string)
	for _, options := range cases {
		for _, executable := range []string{options.executable, options.iperf, options.relayExecutable} {
			if executable == "" {
				continue
			}
			_, loaded := paths[executable]
			if loaded {
				continue
			}
			if request.Local {
				paths[executable], err = filepath.Abs(executable)
				if err != nil {
					return err
				}
				continue
			}
			prefix := "bin/" + strconv.Itoa(len(paths)) + "/"
			paths[executable] = prefix + filepath.Base(executable)
			entries, readErr := os.ReadDir(filepath.Dir(executable))
			if readErr != nil {
				return readErr
			}
			sources := []string{executable}
			for _, entry := range entries {
				if !entry.IsDir() && (strings.HasSuffix(strings.ToLower(entry.Name()), ".dll") || entry.Name() == "msys-kill.exe") {
					sources = append(sources, filepath.Join(filepath.Dir(executable), entry.Name()))
				}
			}
			for _, source := range sources {
				content, openErr := os.Open(source)
				if openErr != nil {
					return openErr
				}
				info, statErr := content.Stat()
				if statErr != nil {
					content.Close()
					return statErr
				}
				if !info.Mode().IsRegular() {
					content.Close()
					return E.New("not a regular executable or dependency: ", source)
				}
				err = archive.WriteHeader(&tar.Header{Name: prefix + filepath.Base(source), Mode: 0o755, Size: info.Size()})
				if err == nil {
					_, err = io.Copy(archive, content)
				}
				err = E.Errors(err, content.Close())
				if err != nil {
					return err
				}
			}
		}
		request.Cases = append(request.Cases, workerCase{
			Case:     options.caseConfiguration,
			Software: options.software, Executable: paths[options.executable], Package: options.sourcePackage, Version: options.version, Iperf: paths[options.iperf], IperfArch: options.iperfArchitecture, Relay: paths[options.relayExecutable],
		})
	}
	content, err := json.Marshal(request)
	if err != nil {
		return err
	}
	err = archive.WriteHeader(&tar.Header{Name: "request.json", Mode: 0o600, Size: int64(len(content))})
	if err != nil {
		return err
	}
	_, err = archive.Write(content)
	return err
}

func runWorker(ctx context.Context, input io.Reader, output io.Writer, bundlePath string) error {
	var size uint64
	bundleInput := input
	var err error
	if bundlePath == "" {
		err = binary.Read(input, binary.BigEndian, &size)
		if err != nil {
			return E.Cause(err, "read bundle size")
		}
	} else {
		file, openErr := os.Open(bundlePath)
		if openErr != nil {
			return openErr
		}
		defer file.Close()
		info, statErr := file.Stat()
		if statErr != nil {
			return statErr
		}
		size, bundleInput = uint64(info.Size()), file
	}
	if size > 16<<30 {
		return E.New("worker bundle exceeds 16 GiB")
	}
	cache, err := cacheDirectory()
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp(cache, "worker-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	limited := &io.LimitedReader{R: bundleInput, N: int64(size)}
	archive := tar.NewReader(limited)
	for {
		entry, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return E.Cause(nextErr, "read worker bundle")
		}
		if !filepath.IsLocal(entry.Name) || strings.Contains(entry.Name, "\\") || entry.Typeflag != tar.TypeReg {
			return E.New("invalid worker bundle entry: ", entry.Name)
		}
		destination := filepath.Join(directory, filepath.FromSlash(entry.Name))
		err = os.MkdirAll(filepath.Dir(destination), 0o700)
		if err != nil {
			return err
		}
		err = writeReleaseFile(destination, archive)
		if err != nil {
			return err
		}
	}
	_, err = io.Copy(io.Discard, limited)
	if err != nil {
		return err
	}
	if limited.N != 0 {
		return io.ErrUnexpectedEOF
	}
	content, err := os.ReadFile(filepath.Join(directory, "request.json"))
	if err != nil {
		return err
	}
	var request workerRequest
	err = json.Unmarshal(content, &request)
	if err != nil {
		return err
	}
	if request.OS != runtime.GOOS || request.Arch != runtime.GOARCH {
		return E.New("worker platform differs: expected ", request.OS, "/", request.Arch, ", got ", runtime.GOOS, "/", runtime.GOARCH)
	}
	var cases []benchmarkOptions
	for _, entry := range request.Cases {
		executable, iperf, relay := entry.Executable, entry.Iperf, entry.Relay
		if request.Local {
			if !filepath.IsAbs(executable) || (iperf != "" && !filepath.IsAbs(iperf)) || (relay != "" && !filepath.IsAbs(relay)) {
				return E.New("local worker requires absolute executable paths")
			}
		} else {
			if !filepath.IsLocal(executable) || (iperf != "" && !filepath.IsLocal(iperf)) || (relay != "" && !filepath.IsLocal(relay)) {
				return E.New("worker executable must be inside bundle")
			}
			executable = filepath.Join(directory, filepath.FromSlash(executable))
			if iperf != "" {
				iperf = filepath.Join(directory, filepath.FromSlash(iperf))
			}
			if relay != "" {
				relay = filepath.Join(directory, filepath.FromSlash(relay))
			}
		}
		cases = append(cases, benchmarkOptions{
			caseConfiguration: entry.Case,
			environmentName:   request.Environment, operatingSystem: request.OS,
			software: entry.Software, sourcePackage: entry.Package, version: entry.Version,
			executable: executable, iperf: iperf, iperfArchitecture: entry.IperfArch, relayExecutable: relay,
		})
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		var control [1]byte
		_, _ = input.Read(control[:])
		cancel()
	}()
	encoder := json.NewEncoder(output)
	runner := benchmarkMatrix{directory: directory, cases: cases, report: request.Report, failFast: request.FailFast, allowVirtualMachine: request.AllowVirtualMachine, saveReport: func(report *benchmarkReport, started *caseResult) error {
		return encoder.Encode(workerUpdate{Report: report, Started: started})
	}}
	return runner.run(ctx)
}

type benchmarkMatrix struct {
	allowVirtualMachine bool
	directory           string
	cases               []benchmarkOptions
	environment         environment
	failFast            bool
	report              *benchmarkReport
	caseIndexes         []int
	saveReport          func(*benchmarkReport, *caseResult) error
}

func (m *benchmarkMatrix) run(ctx context.Context) (returnErr error) {
	var err error
	m.environment, err = preparePlatform(m.allowVirtualMachine)
	if err != nil {
		return err
	}
	for i := range m.cases {
		m.cases[i].resolveQueues(m.environment)
	}
	m.cases = common.Uniq(m.cases)
	err = m.prepareReport()
	if err != nil {
		return err
	}
	completed := 0
	bugs := 0
	for _, index := range m.caseIndexes {
		switch m.report.Cases[index].Status {
		case "passed":
			completed++
		case "bug":
			completed++
			bugs++
		}
	}
	log.Info("Environment ", m.cases[0].environmentName, ": ", completed-bugs, " passed, ", bugs, " bugs; ", len(m.cases)-completed, " to run")
	if completed == len(m.cases) {
		return nil
	}
	throughput := common.Find(m.cases, func(options benchmarkOptions) bool { return options.Type != "memory" })
	var iperfVersion string
	if throughput.Implementation != "" && m.report.Iperf.Version != "" && slices.ContainsFunc(m.report.Cases, func(recorded caseResult) bool { return recorded.Sample != nil }) {
		iperfVersion, err = checkIperf(ctx, throughput.iperf)
		if err != nil {
			return err
		}
		if m.report.Iperf.Version != iperfVersion {
			return E.New("result iperf3 version differs; use another output path or --overwrite")
		}
		if throughput.iperfArchitecture != m.report.Iperf.Arch {
			return E.New("result iperf3 architecture differs; use another output path or --overwrite")
		}
	}
	m.report.FinishedAt, m.report.Error = nil, ""
	defer func() {
		finished := time.Now().UTC()
		m.report.FinishedAt = &finished
		if returnErr != nil {
			m.report.Error = returnErr.Error()
			for _, index := range m.caseIndexes {
				unfinished := &m.report.Cases[index]
				if unfinished.Status == "running" {
					unfinished.Status, unfinished.Error = "failed", returnErr.Error()
					if ctx.Err() != nil {
						unfinished.Status = "canceled"
					}
				}
			}
		}
		returnErr = E.Append(returnErr, m.saveReport(m.report, nil), func(saveErr error) error { return E.Cause(saveErr, "save results") })
	}()
	err = m.saveReport(m.report, nil)
	if err != nil {
		return err
	}
	if throughput.Implementation != "" && iperfVersion == "" {
		iperfVersion, err = checkIperf(ctx, throughput.iperf)
		if err != nil {
			return err
		}
	}
	if throughput.Implementation != "" {
		m.report.Iperf = implementationConfiguration{Type: "iperf3", Path: throughput.iperf, Version: iperfVersion, Arch: throughput.iperfArchitecture}
	}
	failed := false
	for i, options := range m.cases {
		err = ctx.Err()
		if err != nil {
			return err
		}
		recorded := &m.report.Cases[m.caseIndexes[i]]
		if recorded.Status == "passed" || recorded.Status == "bug" {
			continue
		}
		recorded.Status, recorded.Error = "running", ""
		recorded.Bug = nil
		recorded.Sample, recorded.Memory = nil, nil
		if options.Type == "memory" {
			recorded.Memory = &memoryResult{
				ConnectionStep: memoryConnectionStep, MaxConnections: memoryMaxConnections,
				Protocol: currentMemoryProtocol, Metric: memoryMetric,
			}
		}
		recorded.Parallel, recorded.Queues = options.Parallel, options.queues
		err = m.saveReport(m.report, recorded)
		if err != nil {
			return err
		}
		runner := benchmark{
			options: options, environment: m.environment, matrix: m, result: recorded,
		}
		err = runner.run(ctx)
		if err != nil {
			recorded.Status, recorded.Error = "failed", err.Error()
			if ctx.Err() != nil {
				recorded.Status = "canceled"
			} else if runner.cleanupErr == nil && runner.recordErr == nil {
				var bugType string
				switch {
				case errors.Is(err, errProcessPanic):
					bugType = "panic"
				case errors.Is(err, errUDPPayloadIntegrity):
					bugType = "udp-payload"
				case errors.Is(err, errUDPNoPayload):
					bugType = "udp-no-payload"
				}
				if bugType != "" {
					recorded.Bug = &caseBug{Type: bugType, Detail: recorded.Error}
					recorded.Status, recorded.Error = "bug", ""
				}
			}
		} else {
			recorded.Status = "passed"
		}
		saveErr := m.saveReport(m.report, nil)
		if saveErr != nil {
			return E.Errors(err, E.Cause(saveErr, "save results"))
		}
		if recorded.Status == "bug" {
			log.Info(options, ": bug (", recorded.Bug.Type, "); diagnostics saved in results")
			continue
		}
		if err != nil {
			if m.failFast || ctx.Err() != nil || runner.cleanupErr != nil || runner.recordErr != nil {
				return E.Cause(err, "matrix case ", i+1, " (", options, ")")
			}
			log.Error(options, ": ", err)
			failed = true
			continue
		}
	}
	if failed {
		return E.New("one or more benchmark cases failed")
	}
	return nil
}

func (m *benchmarkMatrix) prepareReport() error {
	hostname, err := os.Hostname()
	if err != nil {
		return E.Cause(err, "read hostname")
	}
	placement := resultEnvironment{
		OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname,
		Metric: m.environment.metric, Description: m.environment.description,
		TunnelCPUs: m.environment.cpus, HelperCPUs: m.environment.helperCPUs,
		TunnelWorkers: m.environment.workers, HelperWorkers: m.environment.helpers,
	}
	if m.report == nil {
		m.report = &benchmarkReport{
			StartedAt: time.Now().UTC(), Environment: placement, Protocol: currentProtocol,
			Implementations: make(map[string]implementationConfiguration), Cases: []caseResult{},
		}
	} else {
		measured := slices.ContainsFunc(m.report.Cases, func(recorded caseResult) bool { return recorded.measured() })
		if measured {
			previous := m.report.Environment
			if previous.OS != placement.OS || previous.Arch != placement.Arch || previous.Hostname != placement.Hostname ||
				previous.Metric != placement.Metric || previous.TunnelWorkers != placement.TunnelWorkers || previous.HelperWorkers != placement.HelperWorkers ||
				!slices.Equal(previous.TunnelCPUs, placement.TunnelCPUs) || !slices.Equal(previous.HelperCPUs, placement.HelperCPUs) {
				return E.New("result environment differs; use another output path or --overwrite")
			}
		}
		m.report.Environment = placement
		m.report.Protocol = currentProtocol
	}
	m.caseIndexes = make([]int, len(m.cases))
	for i := range m.cases {
		options := &m.cases[i]
		_, loaded := m.report.Implementations[options.Implementation]
		if !loaded {
			m.report.Implementations[options.Implementation] = implementationConfiguration{
				Type: options.software, Path: options.executable, Package: options.sourcePackage, Version: options.version,
			}
		}
		implementation := m.report.Implementations[options.Implementation]
		implementation.Path = options.executable
		m.report.Implementations[options.Implementation] = implementation
		index := slices.IndexFunc(m.report.Cases, func(recorded caseResult) bool {
			return recorded.matches(*options)
		})
		if index < 0 {
			index = len(m.report.Cases)
			recorded := caseResult{caseConfiguration: options.caseConfiguration, Queues: options.queues, Status: "pending"}
			if options.Type == "memory" {
				recorded.Memory = &memoryResult{
					ConnectionStep: memoryConnectionStep, MaxConnections: memoryMaxConnections,
					Protocol: currentMemoryProtocol, Metric: memoryMetric,
				}
			}
			m.report.Cases = append(m.report.Cases, recorded)
		}
		m.caseIndexes[i] = index
	}
	return nil
}
