package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

type environmentConfiguration struct {
	AllowVirtualMachine bool   `yaml:"allow-virtual-machine" json:"allow_virtual_machine,omitempty"`
	Type                string `yaml:"type" json:"type"`
	OS                  string `yaml:"os" json:"os"`
	Arch                string `yaml:"arch" json:"arch"`
	Device              string `yaml:"device" json:"device,omitempty"`
	Name                string `yaml:"name" json:"name,omitempty"`
	Host                string `yaml:"host" json:"host,omitempty"`
	User                string `yaml:"user" json:"user,omitempty"`
	Port                int    `yaml:"port" json:"port,omitempty"`
	IdentityFile        string `yaml:"identity-file" json:"identity_file,omitempty"`
}

func (e *environmentConfiguration) applyDefaults() {
	if e.Type == "" {
		e.Type = "local"
	}
	if e.Type == "local" {
		if e.OS == "" {
			e.OS = runtime.GOOS
		}
		if e.Arch == "" {
			e.Arch = runtime.GOARCH
		}
	}
	if e.Type == "orbstack" && e.OS == "" {
		e.OS = "linux"
	}
	if (e.Type == "ssh" || e.Type == "orbstack") && e.User == "" {
		e.User = "root"
		if e.OS == "windows" {
			e.User = "administrator"
		}
	}
}

func (e environmentConfiguration) validate() error {
	if !slices.Contains([]string{"darwin", "linux", "windows"}, e.OS) {
		return E.New("os must be darwin, linux or windows")
	}
	architectures := []string{"amd64", "arm64"}
	if e.OS == "linux" {
		architectures = append(architectures, "386", "arm", "loong64", "mips", "mipsle", "mips64", "mips64le", "ppc64", "ppc64le", "riscv64", "s390x")
	}
	if e.OS == "windows" {
		architectures = append(architectures, "386")
	}
	if !slices.Contains(architectures, e.Arch) {
		return E.New("unsupported architecture for ", e.OS, ": ", e.Arch)
	}
	switch e.Type {
	case "local":
		if e.OS != runtime.GOOS || e.Arch != runtime.GOARCH {
			return E.New("local environment must match ", runtime.GOOS, "/", runtime.GOARCH)
		}
		if e.Name != "" || e.Host != "" || e.User != "" || e.Port != 0 || e.IdentityFile != "" {
			return E.New("local environment cannot have connection settings")
		}
	case "orbstack":
		if e.OS != "linux" {
			return E.New("orbstack requires os linux")
		}
		if e.Host != "" || e.Port != 0 || e.IdentityFile != "" {
			return E.New("orbstack only accepts name and user as connection settings")
		}
	case "ssh":
		if e.Host == "" || strings.HasPrefix(e.Host, "-") || strings.ContainsAny(e.Host, "\r\n\x00") {
			return E.New("ssh requires a host or SSH config alias")
		}
		if e.Port < 0 || e.Port > 65535 {
			return E.New("invalid SSH port")
		}
		if e.Name != "" {
			return E.New("ssh uses host instead of name")
		}
	default:
		return E.New("environment type must be local, orbstack or ssh")
	}
	return nil
}

func (e environmentConfiguration) executableSuffix() string {
	if e.OS == "windows" {
		return ".exe"
	}
	return ""
}

type runConfiguration struct {
	Implementations map[string]implementationConfiguration `yaml:"implementations"`
	Environments    map[string]environmentConfiguration    `yaml:"environments"`
	Iperf           string                                 `yaml:"iperf3"`
	FailFast        bool                                   `yaml:"fail-fast"`
	Matrix          matrixConfigurations                   `yaml:"matrix"`
}

type implementationConfiguration struct {
	Type    string `yaml:"type" json:"type"`
	Path    string `yaml:"-" json:"path,omitempty"`
	Package string `yaml:"package" json:"package,omitempty"`
	Version string `yaml:"version" json:"version,omitempty"`
	Stack   string `yaml:"stack" json:"stack,omitempty"`
	Arch    string `yaml:"-" json:"arch,omitempty"`
}

type matrixConfiguration struct {
	Name    string                       `yaml:"name"`
	Type    string                       `yaml:"type"`
	Axes    map[string][]any             `yaml:",inline"`
	Include []matrixIncludeConfiguration `yaml:"include"`
	Exclude []map[string]any             `yaml:"exclude"`
}

type matrixIncludeConfiguration struct {
	Filter map[string]any `yaml:"filter"`
	Values map[string]any `yaml:",inline"`
}

type matrixConfigurations []matrixConfiguration

func (m *matrixConfigurations) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		node = &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{node}}
	}
	return node.Decode((*[]matrixConfiguration)(m))
}

func readConfiguration(path, matrixName, measurementType string) (runConfiguration, []benchmarkOptions, error) {
	var configuration runConfiguration
	if measurementType != "" && measurementType != "throughput" && measurementType != "memory" {
		return configuration, nil, E.New("type must be throughput or memory")
	}
	file, err := os.Open(path)
	if err != nil {
		return configuration, nil, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	err = decoder.Decode(&configuration)
	if err != nil {
		return configuration, nil, E.Cause(err, "read configuration")
	}
	var trailing any
	err = decoder.Decode(&trailing)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			err = E.New("expected one YAML document")
		}
		return configuration, nil, err
	}
	if len(configuration.Matrix) == 0 {
		return configuration, nil, E.New("matrix has no cases")
	}
	type matrixEntry struct {
		name            string
		measurementType string
		values          map[string]any
	}
	var entries []matrixEntry
	for i, matrix := range configuration.Matrix {
		name := matrix.Name
		if name == "" {
			name = "matrix-" + strconv.Itoa(i+1)
		}
		if matrixName != "" && name != matrixName {
			continue
		}
		if matrix.Type == "" {
			matrix.Type = "throughput"
		}
		if matrix.Type != "throughput" && matrix.Type != "memory" {
			return configuration, nil, E.New("matrix ", name, ": type must be throughput or memory")
		}
		if measurementType != "" && matrix.Type != measurementType {
			continue
		}
		expanded, expandErr := matrix.expand()
		if expandErr != nil {
			return configuration, nil, E.Cause(expandErr, "matrix ", i+1)
		}
		for _, entry := range expanded {
			entries = append(entries, matrixEntry{name, matrix.Type, entry})
		}
	}
	if matrixName != "" && len(entries) == 0 {
		return configuration, nil, E.New("no cases match matrix ", matrixName, " and type ", measurementType)
	}
	directory, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return configuration, nil, err
	}
	iperf := configuration.Iperf
	if iperf != "" && !filepath.IsAbs(iperf) {
		iperf = filepath.Join(directory, iperf)
	}
	if len(configuration.Environments) == 0 {
		configuration.Environments = map[string]environmentConfiguration{"local": {Type: "local"}}
	}
	for name, target := range configuration.Environments {
		target.applyDefaults()
		err = target.validate()
		if err != nil {
			return configuration, nil, E.Cause(err, "environment ", name)
		}
		if target.IdentityFile != "" && !filepath.IsAbs(target.IdentityFile) {
			target.IdentityFile = filepath.Join(directory, target.IdentityFile)
		}
		configuration.Environments[name] = target
	}
	resolved := make(map[string]implementationConfiguration)
	var cases []benchmarkOptions
	for i, expanded := range entries {
		entry := expanded.values
		name, _ := entry["implementation"].(string)
		if name == "" {
			return configuration, nil, E.New("matrix case ", i+1, ": implementation is required")
		}
		_, specified := entry["mtu"]
		if !specified {
			return configuration, nil, E.New("matrix case ", i+1, ": mtu is required")
		}
		selector, _ := entry["stack"].(string)
		if selector != "" && !strings.HasPrefix(selector, name+"/") {
			return configuration, nil, E.New("matrix case ", i+1, ": stack ", selector, " does not belong to implementation ", name)
		}
		implementation, loaded := resolved[name]
		if !loaded {
			implementation, loaded = configuration.Implementations[name]
			if !loaded {
				return configuration, nil, E.New("matrix case ", i+1, ": unknown implementation ", name)
			}
			if implementation.Type == "" {
				implementation.Type = name
			}
			switch implementation.Type {
			case "sing-box", "leaf", "mihomo", "hev-socks5-tunnel", "xjasonlyu-tun2socks", "go-tun2socks", "v2ray", "xray":
			default:
				return configuration, nil, E.New("unsupported TUN implementation: ", implementation.Type)
			}
			if implementation.Package != "" && implementation.Version != "" {
				return configuration, nil, E.New(name, ": package and version are mutually exclusive")
			}
			if implementation.Package != "" && implementation.Type != "sing-box" {
				return configuration, nil, E.New(name, ": package is only supported by sing-box")
			}
			if implementation.Package == "" && implementation.Version == "" {
				implementation.Version = "latest"
			}
			implementation.Version = strings.TrimPrefix(implementation.Version, "v")
			if implementation.Version != "" {
				if implementation.Version != "latest" && !semver.IsValid("v"+implementation.Version) {
					return configuration, nil, E.New(name, ": invalid release version ", implementation.Version)
				}
			} else if implementation.Package != "" && !filepath.IsAbs(implementation.Package) {
				implementation.Package = filepath.Join(directory, implementation.Package)
			}
			resolved[name] = implementation
		}
		environmentName, _ := entry["environment"].(string)
		if environmentName == "" {
			if len(configuration.Environments) == 1 {
				for configuredName := range configuration.Environments {
					environmentName = configuredName
				}
			} else {
				return configuration, nil, E.New("matrix case ", i+1, ": environment is required with multiple environments")
			}
		}
		target, loaded := configuration.Environments[environmentName]
		if !loaded {
			return configuration, nil, E.New("unknown environment: ", environmentName)
		}
		options := benchmarkOptions{
			caseConfiguration: caseConfiguration{
				Matrix:         expanded.name,
				Type:           expanded.measurementType,
				Implementation: name,
				Stack:          implementation.Stack,
				Parallel:       1,
			},
			environmentName: environmentName, operatingSystem: target.OS,
			sourcePackage: implementation.Package, software: implementation.Type,
			version: implementation.Version, iperf: iperf,
		}
		for key, value := range entry {
			switch key {
			case "ip":
				options.IP = value.(int)
			case "network":
				options.Network = value.(string)
			case "direction":
				options.Direction = value.(string)
			case "mtu":
				options.MTU = value.(int)
			case "parallel":
				options.Parallel = value.(int)
			case "bitrate":
				options.Bitrate = value.(uint64)
			case "stack":
				_, options.Stack, _ = strings.Cut(value.(string), "/")
			}
		}
		err = options.validate()
		if err != nil {
			return configuration, nil, E.Cause(err, "matrix case ", i+1, " (", name, ")")
		}
		cases = append(cases, options)
	}
	var supported []benchmarkOptions
	for _, options := range common.Uniq(cases) {
		target := configuration.Environments[options.environmentName]
		var reason string
		switch {
		case options.software == "go-tun2socks" && target.OS == "windows":
			reason = "go-tun2socks Windows TAP tests are not supported"
		case options.software == "go-tun2socks" && options.MTU > 1500:
			reason = "go-tun2socks has a fixed 1500-byte TUN read buffer"
		case options.software == "v2ray" && (target.OS != "linux" || target.Arch != "amd64" && target.Arch != "arm64"):
			reason = "v2ray TUN requires linux/amd64 or linux/arm64"
		case options.Type == "throughput" && target.OS == "windows" && options.Network == "udp" && options.Parallel > 1:
			reason = "iperf3 does not support parallel UDP streams on Windows"
		}
		if reason != "" {
			log.Warn("Skipped ", options, ": ", reason)
			continue
		}
		supported = append(supported, options)
	}
	return configuration, supported, nil
}

func (m matrixConfiguration) expand() ([]map[string]any, error) {
	keys := slices.Collect(maps.Keys(m.Axes))
	for _, included := range m.Include {
		keys = append(keys, slices.Collect(maps.Keys(included.Values))...)
		keys = append(keys, slices.Collect(maps.Keys(included.Filter))...)
	}
	for _, excluded := range m.Exclude {
		keys = append(keys, slices.Collect(maps.Keys(excluded))...)
	}
	for _, key := range keys {
		if m.Type == "memory" && slices.Contains([]string{"direction", "parallel", "bitrate"}, key) {
			return nil, E.New("matrix.", key, " is not supported for ", m.Type)
		}
	}
	type matrixInclude struct {
		values   map[string][]any
		filter   map[string][]any
		variants []map[string]any
	}
	includes := make([]matrixInclude, len(m.Include))
	for i, included := range m.Include {
		values, err := normalizeMatrixValues(included.Values)
		if err != nil {
			return nil, E.Cause(err, "include ", i+1)
		}
		var filter map[string][]any
		if included.Filter != nil {
			filter, err = normalizeMatrixValues(included.Filter)
			if err != nil {
				return nil, E.Cause(err, "include ", i+1, " filter")
			}
		}
		variants := []map[string]any{{}}
		for _, key := range slices.Sorted(maps.Keys(values)) {
			var combinations []map[string]any
			for _, variant := range variants {
				for _, value := range values[key] {
					combination := maps.Clone(variant)
					combination[key] = value
					combinations = append(combinations, combination)
				}
			}
			variants = combinations
		}
		includes[i] = matrixInclude{values: values, filter: filter, variants: variants}
	}
	var original []map[string]any
	var stacks []string
	if len(m.Axes) > 0 {
		original = []map[string]any{{}}
	}
	for _, name := range slices.Sorted(maps.Keys(m.Axes)) {
		values := m.Axes[name]
		if len(values) == 0 {
			return nil, E.New("matrix.", name, " must not be empty")
		}
		var expanded []map[string]any
		for _, value := range values {
			normalized, err := normalizeMatrixValue(name, value)
			if err != nil {
				return nil, err
			}
			if name == "stack" {
				stacks = append(stacks, normalized.(string))
				continue
			}
			for _, current := range original {
				variant := maps.Clone(current)
				variant[name] = normalized
				expanded = append(expanded, variant)
			}
		}
		if name != "stack" {
			original = expanded
		}
	}
	original = common.FlatMap(original, func(entry map[string]any) []map[string]any {
		name, _ := entry["implementation"].(string)
		selected := common.Filter(stacks, func(stack string) bool { return name == "" || strings.HasPrefix(stack, name+"/") })
		if len(selected) == 0 {
			return []map[string]any{entry}
		}
		return common.Map(selected, func(stack string) map[string]any {
			variant := maps.Clone(entry)
			variant["stack"] = stack
			return variant
		})
	})
	for _, excluded := range m.Exclude {
		for key, value := range excluded {
			normalized, err := normalizeMatrixValue(key, value)
			if err != nil {
				return nil, err
			}
			excluded[key] = normalized
		}
		original = common.Filter(original, func(entry map[string]any) bool {
			for key, value := range excluded {
				if entry[key] != value {
					return true
				}
			}
			return false
		})
	}
	var configured []map[string]any
	for _, entry := range original {
		_, specified := entry["mtu"]
		if specified {
			configured = append(configured, entry)
			continue
		}
		completed := false
		for _, included := range includes {
			values, supplied := included.values["mtu"]
			if !supplied || len(included.values) != 1 || !matchesMatrixFilter(entry, included.filter) {
				continue
			}
			for _, value := range values {
				candidate := maps.Clone(entry)
				candidate["mtu"] = value
				configured = append(configured, candidate)
				completed = true
			}
		}
		if !completed {
			configured = append(configured, entry)
		}
	}
	original = configured
	expanded := slices.Clone(original)
	for _, included := range includes {
		sources := original
		if included.filter != nil {
			sources = expanded
		}
		for _, overrides := range included.variants {
			applied := false
			for _, entry := range sources {
				if !matchesMatrixFilter(entry, included.filter) {
					continue
				}
				candidate := maps.Clone(entry)
				maps.Copy(candidate, overrides)
				name, _ := candidate["implementation"].(string)
				stack, _ := candidate["stack"].(string)
				if name != "" && stack != "" && !strings.HasPrefix(stack, name+"/") {
					continue
				}
				expanded = append(expanded, candidate)
				applied = true
			}
			if !applied && included.filter == nil {
				expanded = append(expanded, maps.Clone(overrides))
			}
		}
	}
	if len(expanded) == 0 {
		return nil, E.New("matrix has no cases")
	}
	for _, axis := range []struct {
		name   string
		values []any
	}{
		{"ip", []any{4, 6}}, {"network", []any{"tcp", "udp"}}, {"direction", []any{"upload", "download"}},
	} {
		if m.Type == "memory" && axis.name == "direction" {
			continue
		}
		expanded = common.FlatMap(expanded, func(entry map[string]any) []map[string]any {
			_, specified := entry[axis.name]
			if specified {
				return []map[string]any{entry}
			}
			return common.Map(axis.values, func(value any) map[string]any {
				variant := maps.Clone(entry)
				variant[axis.name] = value
				return variant
			})
		})
	}
	return expanded, nil
}

func normalizeMatrixValues(valuesByKey map[string]any) (map[string][]any, error) {
	normalized := make(map[string][]any, len(valuesByKey))
	for key, value := range valuesByKey {
		values, listed := value.([]any)
		if !listed {
			values = []any{value}
		}
		if len(values) == 0 {
			return nil, E.New("matrix.", key, " must not be empty")
		}
		for _, current := range values {
			normalizedValue, err := normalizeMatrixValue(key, current)
			if err != nil {
				return nil, err
			}
			normalized[key] = append(normalized[key], normalizedValue)
		}
	}
	return normalized, nil
}

func matchesMatrixFilter(entry map[string]any, filter map[string][]any) bool {
	for key, values := range filter {
		if !slices.Contains(values, entry[key]) {
			return false
		}
	}
	return true
}

func normalizeMatrixValue(key string, value any) (any, error) {
	switch key {
	case "stack":
		selector, ok := value.(string)
		name, stack, specified := strings.Cut(selector, "/")
		if !ok || !specified || name == "" || stack == "" || strings.Contains(stack, "/") {
			return nil, E.New("matrix.stack requires <implementation-name>/<stack-name>: ", value)
		}
	case "environment", "implementation", "network", "direction":
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, E.New("matrix.", key, " requires a nonempty string")
		}
	case "ip", "mtu", "parallel":
		number, err := strconv.Atoi(fmt.Sprint(value))
		if err != nil {
			return nil, E.Cause(err, "matrix.", key)
		}
		return number, nil
	case "bitrate":
		number, err := strconv.ParseUint(fmt.Sprint(value), 10, 64)
		if err == nil {
			return number, nil
		}
		var rate byteformats.NetworkBytes
		err = rate.UnmarshalJSON([]byte(strconv.Quote(fmt.Sprint(value))))
		if err != nil {
			return nil, E.Cause(err, "matrix.", key)
		}
		if rate.Value() > math.MaxUint64/8 {
			return nil, E.New("matrix.bitrate exceeds uint64 bits/s: ", value)
		}
		return rate.Value() * 8, nil
	default:
		return nil, E.New("unknown matrix axis: ", key)
	}
	return value, nil
}
