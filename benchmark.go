package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"gopkg.in/yaml.v3"
)

type environment struct {
	metric        resourceMetric
	description   string
	workers       int
	helpers       int
	interfaceName string
	address       netip.Prefix
	target        netip.Addr
	cpus          []int
	helperCPUs    []int
}

type benchmark struct {
	options     benchmarkOptions
	environment environment
	directory   string
	port        int
	serverPorts []int
	server      *process
	tunnels     []*process
	relay       *process
	memoryLoad  *memoryLoad
	routeIndex  int
	matrix      *benchmarkMatrix
	result      *caseResult
	recordErr   error
	cleanupErr  error
}

func (b *benchmark) run(ctx context.Context) (returnErr error) {
	defer func() {
		processes := append(slices.Clone(b.tunnels), b.relay, b.server)
		for _, child := range b.tunnels {
			returnErr = E.Errors(returnErr, child.check())
		}
		if b.relay != nil {
			returnErr = E.Errors(returnErr, b.relay.check())
		}
		b.cleanupErr = b.Close()
		returnErr = E.Append(returnErr, b.cleanupErr, func(closeErr error) error { return E.Cause(closeErr, "clean up benchmark") })
		var logs strings.Builder
		for _, child := range processes {
			if child != nil {
				returnErr = E.Errors(returnErr, child.output.panicError())
				fmt.Fprintf(&logs, "%s (PID %d): %s\n", filepath.Base(child.command.Path), child.command.Process.Pid, child.output.String())
			}
		}
		if returnErr != nil && logs.Len() > 0 {
			returnErr = E.Extend(returnErr, "\n", logs.String())
		}
	}()
	err := prepareNetwork(ctx, b.options, &b.environment)
	if err != nil {
		return err
	}
	b.directory, err = os.MkdirTemp(b.matrix.directory, "run-*")
	if err != nil {
		return E.Cause(err, "create working directory")
	}
	if b.options.Type == "memory" {
		return b.runMemory(ctx)
	}
	return b.runThroughput(ctx)
}

func (b *benchmark) startTunnel(ctx context.Context) error {
	var err error
	probePort := 0
	if b.options.Type != "memory" {
		var probe net.Listener
		probe, err = net.Listen("tcp", net.JoinHostPort(b.options.loopback(), "0"))
		if err != nil {
			return E.Cause(err, "listen for forwarding probe")
		}
		defer probe.Close()
		go serveProbe(probe, b.environment.interfaceName)
		probePort = probe.Addr().(*net.TCPAddr).Port
		if b.options.Network == "udp" {
			packetProbe, listenErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(b.options.loopback()), Port: probePort})
			if listenErr != nil {
				return E.Cause(listenErr, "listen for UDP forwarding probe")
			}
			defer packetProbe.Close()
			err = E.Errors(packetProbe.SetReadBuffer(4<<20), packetProbe.SetWriteBuffer(4<<20))
			if err != nil {
				return E.Cause(err, "set UDP probe socket buffers")
			}
			go servePacketProbe(packetProbe, b.environment.interfaceName, b.options.udpPayloadLength(), b.options.Direction)
		}
	}
	err = b.startSubject(context.WithoutCancel(ctx), probePort)
	if err != nil {
		return err
	}
	var tunnelInterface *net.Interface
	configured := b.options.software == "sing-box" || b.options.software == "mihomo" && runtime.GOOS == "windows"
	err = waitUntil(ctx, func() (bool, error) {
		processErr := verifyProcesses(b.tunnels)
		if processErr != nil {
			return false, processErr
		}
		var interfaceErr error
		tunnelInterface, interfaceErr = net.InterfaceByName(b.environment.interfaceName)
		if interfaceErr != nil {
			return false, nil
		}
		if !configured {
			configured, interfaceErr = configureInterface(ctx, b.options, b.environment, tunnelInterface)
			return false, interfaceErr
		}
		if tunnelInterface.Flags&net.FlagUp == 0 {
			return false, nil
		}
		return prepareInterface(b.options, b.environment, tunnelInterface)
	})
	if err != nil {
		return E.Cause(err, "wait for TUN interface")
	}
	err = updateRoute(ctx, b.environment, tunnelInterface.Index, "add")
	if err != nil {
		return E.Cause(err, "add test route")
	}
	b.routeIndex = tunnelInterface.Index
	if b.options.Type == "memory" {
		return nil
	}
	var probeErr error
	err = waitUntil(ctx, func() (bool, error) {
		processErr := verifyProcesses(b.tunnels)
		if processErr != nil {
			return false, processErr
		}
		probeErr = probeTunnel(ctx, net.JoinHostPort(b.environment.target.String(), strconv.Itoa(probePort)), b.environment.interfaceName)
		return probeErr == nil, nil
	})
	if err != nil {
		return E.Cause(E.Errors(err, probeErr), "wait for TUN forwarding")
	}
	if b.options.Network == "udp" {
		err = probePacketTunnel(ctx, net.JoinHostPort(b.environment.target.String(), strconv.Itoa(probePort)), b.environment.interfaceName, b.options.udpPayloadLength(), b.options.Direction)
		if err != nil {
			return E.Cause(err, "verify UDP forwarding at MTU ", b.options.MTU)
		}
	}
	return nil
}

func (b *benchmark) Close() error {
	var err error
	for _, child := range b.tunnels {
		child.cancel()
	}
	for _, child := range append(slices.Clone(b.tunnels), b.relay, b.server) {
		if child != nil {
			err = E.Errors(err, child.stop())
		}
	}
	if b.memoryLoad != nil {
		b.memoryLoad.Close()
		b.memoryLoad = nil
	}
	if b.routeIndex != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		isTunnel := func(networkInterface net.Interface) bool {
			return networkInterface.Index == b.routeIndex && networkInterface.Name == b.environment.interfaceName
		}
		interfaces, inspectErr := net.Interfaces()
		routeErr := inspectErr
		if routeErr == nil && slices.ContainsFunc(interfaces, isTunnel) {
			routeErr = updateRoute(ctx, b.environment, b.routeIndex, "delete")
			if routeErr != nil {
				interfaces, inspectErr = net.Interfaces()
				if inspectErr == nil && !slices.ContainsFunc(interfaces, isTunnel) {
					routeErr = nil
				}
			}
		}
		err = E.Errors(err, routeErr)
		cancel()
		b.routeIndex = 0
	}
	if len(b.tunnels) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		interfaceErr := waitUntil(ctx, func() (bool, error) {
			interfaces, inspectErr := net.Interfaces()
			if inspectErr != nil {
				return false, inspectErr
			}
			return !slices.ContainsFunc(interfaces, func(networkInterface net.Interface) bool {
				return networkInterface.Name == b.environment.interfaceName
			}), nil
		})
		cancel()
		err = E.Append(err, interfaceErr, func(releaseErr error) error {
			return E.Cause(releaseErr, "wait for TUN interface ", b.environment.interfaceName, " to be removed")
		})
	}
	b.tunnels, b.relay, b.server = nil, nil, nil
	if b.directory != "" {
		err = E.Append(err, os.RemoveAll(b.directory), func(removeErr error) error { return E.Cause(removeErr, "remove working directory") })
		b.directory = ""
	}
	return err
}

type hevSocks5TunnelConfiguration struct {
	Tunnel struct {
		Name       string `yaml:"name"`
		MTU        int    `yaml:"mtu"`
		MultiQueue bool   `yaml:"multi-queue"`
		IPv4       string `yaml:"ipv4,omitempty"`
		IPv6       string `yaml:"ipv6,omitempty"`
	} `yaml:"tunnel"`
	SOCKS5 struct {
		Address string `yaml:"address"`
		Port    int    `yaml:"port"`
		UDP     string `yaml:"udp"`
	} `yaml:"socks5"`
	Misc struct {
		LogLevel string `yaml:"log-level"`
		LogFile  string `yaml:"log-file"`
	} `yaml:"misc"`
}

func (b *benchmark) startSubject(ctx context.Context, probePort int) error {
	ports := common.Map(b.serverPorts, func(port int) uint16 { return uint16(port) })
	if probePort != 0 {
		ports = append(ports, uint16(probePort))
	}
	targetPrefix := netip.PrefixFrom(b.environment.target, b.environment.target.BitLen()).String()
	var content []byte
	var err error
	var args []string
	count := 1
	relayPort := 0
	relayAddress := "127.0.0.1"
	if b.options.operatingSystem == "darwin" && b.options.Network == "udp" {
		relayAddress = "::1"
	}
	if b.options.relayExecutable != "" {
		relayPort, err = b.startRelay(ctx, relayAddress, probePort)
		if err != nil {
			return err
		}
	}
	path := filepath.Join(b.directory, b.options.software+".json")
	switch b.options.software {
	case "sing-box":
		configuration := option.Options{
			Log: &option.LogOptions{Level: "warn"},
			Inbounds: []option.Inbound{{
				Type: C.TypeTun,
				Options: &option.TunInboundOptions{
					InterfaceName: b.environment.interfaceName,
					Address:       []netip.Prefix{b.environment.address},
					MTU:           uint32(b.options.MTU),
					Stack:         b.options.Stack,
					MultiQueue:    b.options.multiQueue(),
				},
			}},
			Outbounds: []option.Outbound{{
				Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{},
			}},
			Route: &option.RouteOptions{
				Rules: []option.Rule{{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{IPCIDR: []string{targetPrefix}, Port: ports},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: "direct",
								RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{
									OverrideAddress: b.options.loopback(),
								},
							},
						},
					},
				}, {
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RuleAction: option.RuleAction{Action: C.RuleActionTypeReject},
					},
				}},
			},
		}
		content, err = json.Marshal(configuration)
		args = []string{"run", "-c", path}
	case "hev-socks5-tunnel":
		var configuration hevSocks5TunnelConfiguration
		configuration.Tunnel.Name = b.environment.interfaceName
		configuration.Tunnel.MTU = b.options.MTU
		configuration.Tunnel.MultiQueue = b.options.multiQueue()
		if b.options.IP == 6 {
			configuration.Tunnel.IPv6 = b.environment.address.Addr().String()
		} else {
			configuration.Tunnel.IPv4 = b.environment.address.Addr().String()
		}
		configuration.SOCKS5.Address = relayAddress
		configuration.SOCKS5.Port = relayPort
		configuration.SOCKS5.UDP = "udp"
		configuration.Misc.LogLevel = "warn"
		configuration.Misc.LogFile = "stderr"
		content, err = yaml.Marshal(configuration)
		path = filepath.Join(b.directory, "hev-socks5-tunnel.yml")
		args = []string{path}
		count = b.options.queues
	case "xjasonlyu-tun2socks":
		args = []string{"--device", "tun://" + b.environment.interfaceName, "--proxy", "socks5://" + net.JoinHostPort(relayAddress, strconv.Itoa(relayPort)), "--mtu", strconv.Itoa(b.options.MTU), "--loglevel", "warn"}
	case "go-tun2socks":
		mask := net.IP(net.CIDRMask(b.environment.address.Bits(), 32)).String()
		if b.options.IP == 6 {
			mask = strconv.Itoa(b.environment.address.Bits())
		}
		args = []string{
			"-tunName", b.environment.interfaceName,
			"-tunAddr", b.environment.address.Addr().String(),
			"-tunGw", b.environment.address.Addr().Next().String(),
			"-tunMask", mask,
			"-proxyType", "socks", "-proxyServer", net.JoinHostPort(relayAddress, strconv.Itoa(relayPort)),
			"-loglevel", "warn",
		}
	case "leaf":
		settings := map[string]any{
			"name": b.environment.interfaceName, "mtu": b.options.MTU,
			"address": "198.18.0.1", "gateway": "198.18.0.2", "netmask": "255.255.255.248",
			"auto": false,
		}
		if b.options.Stack != "" {
			settings["tun2socks"] = b.options.Stack
		}
		if runtime.GOOS == "windows" {
			settings["wintun"] = filepath.Join(filepath.Dir(b.options.executable), "wintun.dll")
		}
		outbounds := []any{map[string]any{"protocol": "drop", "tag": "drop"}}
		var rules []any
		for _, port := range ports {
			portText := strconv.Itoa(int(port))
			tag := "direct-" + portText
			outbounds = append(outbounds, map[string]any{
				"protocol": "redirect", "tag": tag,
				"settings": map[string]any{"address": b.options.loopback(), "port": port},
			})
			rules = append(rules, map[string]any{
				"ip": []string{targetPrefix}, "portRange": []string{portText + "-" + portText}, "target": tag,
			})
		}
		content, err = json.Marshal(map[string]any{
			"log":       map[string]any{"level": "warn", "output": "console"},
			"inbounds":  []any{map[string]any{"protocol": "tun", "tag": "tun-in", "settings": settings}},
			"outbounds": outbounds,
			"router":    map[string]any{"rules": rules, "domainResolve": false},
		})
		args = []string{"--config", path}
	case "mihomo":
		stack := b.options.Stack
		if stack == "" {
			stack = "gvisor"
		}
		listener := map[string]any{
			"name": "tun-in", "type": "tun", "device": b.environment.interfaceName,
			"stack": stack, "mtu": b.options.MTU, "auto-route": false, "auto-detect-interface": false,
		}
		if b.options.IP == 6 {
			listener["inet6-address"] = []string{b.environment.address.String()}
		} else {
			listener["inet4-address"] = []string{b.environment.address.String()}
		}
		content, err = yaml.Marshal(map[string]any{
			"mode": "rule", "log-level": "warning", "ipv6": true, "find-process-mode": "off",
			"listeners": []any{listener},
			"proxies":   []any{map[string]any{"name": "relay", "type": "socks5", "server": relayAddress, "port": relayPort, "udp": true}},
			"rules":     []string{"MATCH,relay"}, "dns": map[string]any{"enable": false},
		})
		path = filepath.Join(b.directory, "mihomo.yaml")
		args = []string{"-f", path, "-d", b.directory}
	case "v2ray", "xray":
		portList := strings.Join(common.Map(ports, func(port uint16) string { return strconv.Itoa(int(port)) }), ",")
		settings := map[string]any{"redirect": net.JoinHostPort(b.options.loopback(), "0")}
		routingKey := "routing"
		routing := map[string]any{"rules": []any{map[string]any{
			"type": "field", "ip": []string{targetPrefix}, "port": portList, "outboundTag": "direct",
		}}}
		configuration := map[string]any{
			"log": map[string]any{"loglevel": "warning", "access": "none"},
		}
		args = []string{"run", "-c", path}
		if b.options.software == "v2ray" {
			routingKey = "router"
			routing = map[string]any{"rule": []any{map[string]any{
				"tag": "direct", "portList": portList,
				"geoip": []any{map[string]any{"cidr": []any{map[string]any{
					"ip": b.environment.target.AsSlice(), "prefix": b.environment.target.BitLen(),
				}}}},
			}}}
			configuration["log"] = map[string]any{
				"access": map[string]any{"type": "None"},
				"error":  map[string]any{"type": "Console", "level": "Warning"},
			}
			settings = map[string]any{
				"destinationOverride": map[string]any{
					"server": map[string]any{"address": b.options.loopback()},
				},
			}
			configuration["services"] = map[string]any{
				"tun": map[string]any{
					"name": b.environment.interfaceName, "mtu": b.options.MTU, "tag": "tun-in",
					"enablePromiscuousMode": true, "enableSpoofing": true,
					"ips":    []any{map[string]any{"ip": b.environment.address.Addr().AsSlice(), "prefix": b.environment.address.Bits()}},
					"routes": []any{map[string]any{"ip": b.environment.address.Masked().Addr().AsSlice(), "prefix": b.environment.address.Bits()}},
				},
			}
			args = append(args, "-format", "jsonv5")
		} else {
			configuration["inbounds"] = []any{map[string]any{
				"protocol": "tun", "tag": "tun-in", "port": 0,
				"settings": map[string]any{"name": b.environment.interfaceName, "MTU": b.options.MTU},
			}}
		}
		configuration["outbounds"] = []any{
			map[string]any{"protocol": "blackhole", "tag": "drop", "settings": map[string]any{}},
			map[string]any{"protocol": "freedom", "tag": "direct", "settings": settings},
		}
		configuration[routingKey] = routing
		content, err = json.Marshal(configuration)
	default:
		panic("unsupported TUN implementation: " + b.options.software)
	}
	if err != nil {
		return E.Cause(err, "encode ", b.options.software, " configuration")
	}
	if content != nil {
		err = os.WriteFile(path, content, 0o600)
		if err != nil {
			return E.Cause(err, "write configuration")
		}
	}
	for range count {
		var tunnel *process
		tunnel, err = startProcess(ctx, processOptions{
			path: b.options.executable,
			args: args,
			cpus: b.environment.cpus,
			env:  []string{"GOMAXPROCS=" + strconv.Itoa(b.environment.workers)},
		})
		if err != nil {
			return err
		}
		b.tunnels = append(b.tunnels, tunnel)
	}
	return nil
}

func (b *benchmark) startRelay(ctx context.Context, address string, probePort int) (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	err = listener.Close()
	if err != nil {
		return 0, err
	}
	ports := common.Map(b.serverPorts, func(serverPort int) uint16 { return uint16(serverPort) })
	if probePort != 0 {
		ports = append(ports, uint16(probePort))
	}
	configuration := option.Options{
		Log: &option.LogOptions{Level: "warn"},
		Inbounds: []option.Inbound{{
			Type: C.TypeSOCKS,
			Options: &option.SocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     new(badoption.Addr(netip.MustParseAddr(address))),
					ListenPort: uint16(port),
				},
			},
		}},
		Outbounds: []option.Outbound{{
			Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{},
		}},
		Route: &option.RouteOptions{
			Rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPCIDR: []string{netip.PrefixFrom(b.environment.target, b.environment.target.BitLen()).String()},
						Port:   ports,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: "direct",
							RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{
								OverrideAddress: b.options.loopback(),
							},
						},
					},
				},
			}, {
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RuleAction: option.RuleAction{Action: C.RuleActionTypeReject},
				},
			}},
		},
	}
	content, err := json.Marshal(configuration)
	if err != nil {
		return 0, E.Cause(err, "encode sing-box relay configuration")
	}
	path := filepath.Join(b.directory, "relay.json")
	err = os.WriteFile(path, content, 0o600)
	if err != nil {
		return 0, E.Cause(err, "write sing-box relay configuration")
	}
	b.relay, err = startProcess(context.WithoutCancel(ctx), processOptions{
		path: b.options.relayExecutable,
		args: []string{"run", "-c", path},
		cpus: b.environment.helperCPUs,
		env:  []string{"GOMAXPROCS=" + strconv.Itoa(b.environment.helpers)},
	})
	if err != nil {
		return 0, E.Cause(err, "start sing-box relay")
	}
	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	err = waitUntil(ctx, func() (bool, error) {
		processErr := b.relay.verify()
		if processErr != nil {
			return false, processErr
		}
		conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
		if dialErr != nil {
			return false, nil
		}
		return true, conn.Close()
	})
	if err != nil {
		return 0, E.Cause(err, "wait for sing-box relay")
	}
	return port, nil
}
