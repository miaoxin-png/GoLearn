package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	mdnsPort        = 5353
	mdnsIPv4Address = "224.0.0.251"
	mdnsIPv6Address = "ff02::fb"

	servicesBrowseName = "_services._dns-sd._udp.local"
)

var commonServiceTypes = []string{
	"_workstation._tcp.local",
	"_http._tcp.local",
	"_https._tcp.local",
	"_smb._tcp.local",
	"_qdiscover._tcp.local",
	"_device-info._tcp.local",
	"_afpovertcp._tcp.local",
	"_ssh._tcp.local",
	"_sftp-ssh._tcp.local",
	"_ftp._tcp.local",
	"_ipp._tcp.local",
	"_ipps._tcp.local",
	"_printer._tcp.local",
	"_airplay._tcp.local",
	"_raop._tcp.local",
	"_googlecast._tcp.local",
	"_companion-link._tcp.local",
	"_homekit._tcp.local",
}

type cliOptions struct {
	CIDR     string
	Ports    string
	Timeout  time.Duration
	IFace    string
	Services string
	Passive  bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	opts, err := parseCLI(args, stderr)
	if err != nil {
		return err
	}

	ipFilter, err := parseIPFilter(opts.CIDR)
	if err != nil {
		return err
	}
	portFilter, err := parsePortFilter(opts.Ports)
	if err != nil {
		return err
	}

	serviceQueries := defaultServiceQueries(opts.Services)
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	scanner := newMDNSScanner(opts.IFace, serviceQueries, opts.Passive)
	discovery, err := scanner.Discover(ctx)
	if err != nil {
		return err
	}

	output := formatDiscovery(discovery, ipFilter, portFilter)
	_, err = io.WriteString(stdout, output)
	return err
}

func parseCLI(args []string, stderr io.Writer) (cliOptions, error) {
	var opts cliOptions
	fs := flag.NewFlagSet("mdns-map", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.CIDR, "cidr", "", "target IP CIDR/range, for example 192.168.1.0/24")
	fs.StringVar(&opts.Ports, "ports", "", "target service ports, for example 1-65535 or 80,443,5000-5010")
	fs.DurationVar(&opts.Timeout, "timeout", 6*time.Second, "mDNS discovery timeout")
	fs.StringVar(&opts.IFace, "iface", "", "network interface name, optional")
	fs.StringVar(&opts.Services, "services", "", "comma-separated mDNS service types to query in addition to defaults")
	fs.BoolVar(&opts.Passive, "passive", false, "only listen for mDNS traffic without sending queries")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s -cidr <cidr|ip|ip-ip> -ports <ports>\n", fs.Name())
		fmt.Fprintf(stderr, "       %s <cidr|ip|ip-ip> <ports>\n\n", fs.Name())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return opts, err
	}

	rest := fs.Args()
	if opts.CIDR == "" && len(rest) > 0 {
		opts.CIDR = rest[0]
	}
	if opts.Ports == "" && len(rest) > 1 {
		opts.Ports = rest[1]
	}
	if opts.CIDR == "" {
		return opts, errors.New("missing target IP segment: use -cidr or positional argument")
	}
	if opts.Ports == "" {
		return opts, errors.New("missing target port range: use -ports or positional argument")
	}
	if opts.Timeout <= 0 {
		return opts, errors.New("timeout must be greater than 0")
	}
	return opts, nil
}

func defaultServiceQueries(extra string) []string {
	seen := map[string]bool{}
	var queries []string
	add := func(name string) {
		name = normalizeDNSName(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		queries = append(queries, name)
	}

	add(servicesBrowseName)
	for _, service := range commonServiceTypes {
		add(service)
	}
	for _, service := range strings.Split(extra, ",") {
		add(service)
	}
	return queries
}

type ipRange struct {
	Start netip.Addr
	End   netip.Addr
}

type ipFilter struct {
	Prefixes []netip.Prefix
	Ranges   []ipRange
	Addrs    []netip.Addr
}

func parseIPFilter(input string) (ipFilter, error) {
	var filter ipFilter
	parts := splitCSV(input)
	if len(parts) == 0 {
		return filter, errors.New("empty IP segment")
	}

	for _, part := range parts {
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return filter, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			filter.Prefixes = append(filter.Prefixes, prefix.Masked())
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := netip.ParseAddr(strings.TrimSpace(bounds[0]))
			if err != nil {
				return filter, fmt.Errorf("invalid IP range start %q: %w", bounds[0], err)
			}
			end, err := netip.ParseAddr(strings.TrimSpace(bounds[1]))
			if err != nil {
				return filter, fmt.Errorf("invalid IP range end %q: %w", bounds[1], err)
			}
			if start.BitLen() != end.BitLen() {
				return filter, fmt.Errorf("IP range %q mixes IPv4 and IPv6", part)
			}
			if compareAddr(start, end) > 0 {
				return filter, fmt.Errorf("IP range %q start is greater than end", part)
			}
			filter.Ranges = append(filter.Ranges, ipRange{Start: start, End: end})
			continue
		}

		addr, err := netip.ParseAddr(part)
		if err != nil {
			return filter, fmt.Errorf("invalid IP %q: %w", part, err)
		}
		filter.Addrs = append(filter.Addrs, addr)
	}

	return filter, nil
}

func (f ipFilter) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range f.Prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, item := range f.Ranges {
		if addr.BitLen() == item.Start.BitLen() && compareAddr(addr, item.Start) >= 0 && compareAddr(addr, item.End) <= 0 {
			return true
		}
	}
	for _, item := range f.Addrs {
		if addr == item {
			return true
		}
	}
	return false
}

type portRange struct {
	Start uint16
	End   uint16
}

type portFilter struct {
	Ranges []portRange
}

func parsePortFilter(input string) (portFilter, error) {
	var filter portFilter
	for _, part := range splitCSV(input) {
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := parsePort(bounds[0])
			if err != nil {
				return filter, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return filter, err
			}
			if start > end {
				return filter, fmt.Errorf("invalid port range %q: start is greater than end", part)
			}
			filter.Ranges = append(filter.Ranges, portRange{Start: start, End: end})
			continue
		}

		port, err := parsePort(part)
		if err != nil {
			return filter, err
		}
		filter.Ranges = append(filter.Ranges, portRange{Start: port, End: port})
	}

	if len(filter.Ranges) == 0 {
		return filter, errors.New("empty port range")
	}
	return filter, nil
}

func (f portFilter) Contains(port uint16) bool {
	for _, item := range f.Ranges {
		if port >= item.Start && port <= item.End {
			return true
		}
	}
	return false
}

func parsePort(input string) (uint16, error) {
	port64, err := strconv.ParseUint(strings.TrimSpace(input), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", input, err)
	}
	if port64 == 0 {
		return 0, fmt.Errorf("invalid port %q: port must be in 1-65535", input)
	}
	return uint16(port64), nil
}

type mdnsScanner struct {
	ifaceName string
	queries   []string
	passive   bool
}

func newMDNSScanner(ifaceName string, queries []string, passive bool) mdnsScanner {
	return mdnsScanner{
		ifaceName: ifaceName,
		queries:   queries,
		passive:   passive,
	}
}

func (s mdnsScanner) Discover(ctx context.Context) (*discoveryState, error) {
	sockets, err := openMDNSSockets(s.ifaceName)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()

	discovery := newDiscoveryState()
	packetCh := make(chan mdnsPacket, 64)
	var wg sync.WaitGroup
	for _, socket := range sockets {
		wg.Add(1)
		go func(sock mdnsSocket) {
			defer wg.Done()
			readMDNSPackets(ctx, sock, packetCh)
		}(socket)
	}

	if !s.passive {
		s.sendQueries(sockets, s.queries)
	}

	knownQueries := map[string]bool{}
	for _, query := range s.queries {
		knownQueries[query] = true
	}

	ticker := time.NewTicker(1200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			for _, socket := range sockets {
				_ = socket.Close()
			}
			wg.Wait()
			return discovery, nil
		case <-ticker.C:
			if !s.passive {
				var queries []string
				for query := range knownQueries {
					queries = append(queries, query)
				}
				sort.Strings(queries)
				s.sendQueries(sockets, queries)
			}
		case packet := <-packetCh:
			if packet.Err != nil {
				continue
			}
			newServiceTypes := discovery.ApplyPacket(packet)
			if s.passive {
				continue
			}
			for _, serviceType := range newServiceTypes {
				if knownQueries[serviceType] {
					continue
				}
				knownQueries[serviceType] = true
				s.sendQueries(sockets, []string{serviceType})
			}
		}
	}
}

func (s mdnsScanner) sendQueries(sockets []mdnsSocket, names []string) {
	for _, name := range names {
		msg, err := buildPTRQuery(name)
		if err != nil {
			continue
		}
		for _, socket := range sockets {
			_ = socket.WriteQuery(msg)
		}
	}
}

type mdnsSocket struct {
	conn      *net.UDPConn
	network   string
	ifaceName string
}

func (s mdnsSocket) Close() error {
	return s.conn.Close()
}

func (s mdnsSocket) WriteQuery(msg []byte) error {
	if s.network == "udp6" {
		addr := &net.UDPAddr{IP: net.ParseIP(mdnsIPv6Address), Port: mdnsPort, Zone: s.ifaceName}
		_, err := s.conn.WriteToUDP(msg, addr)
		return err
	}
	addr := &net.UDPAddr{IP: net.ParseIP(mdnsIPv4Address), Port: mdnsPort}
	_, err := s.conn.WriteToUDP(msg, addr)
	return err
}

func openMDNSSockets(ifaceName string) ([]mdnsSocket, error) {
	ifaces, err := multicastInterfaces(ifaceName)
	if err != nil {
		return nil, err
	}

	var sockets []mdnsSocket
	var errs []error
	for _, ifi := range ifaces {
		has4, has6 := interfaceFamilies(ifi)
		if has4 {
			socket, err := openMDNSSocket("udp4", ifi)
			if err != nil {
				errs = append(errs, err)
			} else {
				sockets = append(sockets, socket)
			}
		}
		if has6 {
			socket, err := openMDNSSocket("udp6", ifi)
			if err != nil {
				errs = append(errs, err)
			} else {
				sockets = append(sockets, socket)
			}
		}
	}

	if len(sockets) > 0 {
		return sockets, nil
	}

	if ifaceName == "" {
		socket, err := openMDNSSocket("udp4", nil)
		if err == nil {
			return []mdnsSocket{socket}, nil
		}
		errs = append(errs, err)
	}

	return nil, fmt.Errorf("unable to open mDNS listener: %s", joinErrors(errs))
}

func multicastInterfaces(ifaceName string) ([]*net.Interface, error) {
	if ifaceName != "" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
		}
		return []*net.Interface{ifi}, nil
	}

	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ifaces []*net.Interface
	for i := range all {
		ifi := &all[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaces = append(ifaces, ifi)
	}
	return ifaces, nil
}

func interfaceFamilies(ifi *net.Interface) (has4 bool, has6 bool) {
	if ifi == nil {
		return true, true
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false, false
	}
	for _, item := range addrs {
		prefix, err := netip.ParsePrefix(item.String())
		if err != nil {
			continue
		}
		addr := prefix.Addr().Unmap()
		if addr.Is4() {
			has4 = true
		}
		if addr.Is6() {
			has6 = true
		}
	}
	return has4, has6
}

func openMDNSSocket(network string, ifi *net.Interface) (mdnsSocket, error) {
	groupIP := net.ParseIP(mdnsIPv4Address)
	if network == "udp6" {
		groupIP = net.ParseIP(mdnsIPv6Address)
	}
	conn, err := net.ListenMulticastUDP(network, ifi, &net.UDPAddr{IP: groupIP, Port: mdnsPort})
	if err != nil {
		return mdnsSocket{}, err
	}
	_ = conn.SetReadBuffer(512 * 1024)

	if network == "udp4" {
		pc := ipv4.NewPacketConn(conn)
		_ = pc.SetMulticastTTL(255)
		if ifi != nil {
			_ = pc.SetMulticastInterface(ifi)
		}
	} else {
		pc := ipv6.NewPacketConn(conn)
		_ = pc.SetMulticastHopLimit(255)
		if ifi != nil {
			_ = pc.SetMulticastInterface(ifi)
		}
	}

	socket := mdnsSocket{conn: conn, network: network}
	if ifi != nil {
		socket.ifaceName = ifi.Name
	}
	return socket, nil
}

func readMDNSPackets(ctx context.Context, socket mdnsSocket, packetCh chan<- mdnsPacket) {
	buf := make([]byte, 9000)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = socket.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := socket.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case packetCh <- mdnsPacket{Err: err}:
			case <-ctx.Done():
			}
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case packetCh <- mdnsPacket{Data: data, Source: addr.Addr().Unmap()}:
		case <-ctx.Done():
			return
		}
	}
}

type mdnsPacket struct {
	Data   []byte
	Source netip.Addr
	Err    error
}

func buildPTRQuery(name string) ([]byte, error) {
	dnsName, err := dnsmessage.NewName(ensureTrailingDot(name))
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsName,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

type discoveryState struct {
	ServiceTypes      orderedSet
	InstancesByType   map[string]*orderedSet
	Instances         map[string]*instanceState
	Hosts             map[string]*hostState
	ServiceTypeByName map[string]string
}

type instanceState struct {
	FQDN        string
	ServiceType string
	Name        string
	Port        uint16
	Target      string
	HasSRV      bool
	TXT         orderedSet
	TTL         uint32
	SourceIPs   orderedAddrSet
}

type hostState struct {
	Name    string
	IPv4    orderedAddrSet
	IPv6    orderedAddrSet
	TTL     uint32
	Sources orderedAddrSet
}

func newDiscoveryState() *discoveryState {
	return &discoveryState{
		ServiceTypes:      newOrderedSet(),
		InstancesByType:   map[string]*orderedSet{},
		Instances:         map[string]*instanceState{},
		Hosts:             map[string]*hostState{},
		ServiceTypeByName: map[string]string{},
	}
}

func (d *discoveryState) ApplyPacket(packet mdnsPacket) []string {
	resources, err := parseResources(packet.Data)
	if err != nil {
		return nil
	}

	var newServiceTypes []string
	for _, resource := range resources {
		name := normalizeDNSName(resource.Header.Name.String())
		ttl := resource.Header.TTL

		switch body := resource.Body.(type) {
		case *dnsmessage.PTRResource:
			ptr := normalizeDNSName(body.PTR.String())
			if name == servicesBrowseName {
				if isServiceType(ptr) && !d.ServiceTypes.Has(ptr) {
					d.ServiceTypes.Add(ptr)
					newServiceTypes = append(newServiceTypes, ptr)
				}
				continue
			}
			if isServiceType(name) {
				d.addServiceType(name)
				d.addInstance(name, ptr, ttl, packet.Source)
			}
		case *dnsmessage.SRVResource:
			instanceName := normalizeDNSName(name)
			serviceType := d.serviceTypeForInstance(instanceName)
			instance := d.ensureInstance(instanceName, serviceType)
			instance.HasSRV = true
			instance.Port = body.Port
			instance.Target = normalizeDNSName(body.Target.String())
			instance.addTTL(ttl)
			instance.SourceIPs.Add(packet.Source)

			host := d.ensureHost(instance.Target)
			host.addTTL(ttl)
			host.Sources.Add(packet.Source)
			if packet.Source.IsValid() && !packet.Source.IsLoopback() {
				host.addAddress(packet.Source)
			}
		case *dnsmessage.TXTResource:
			instanceName := normalizeDNSName(name)
			serviceType := d.serviceTypeForInstance(instanceName)
			instance := d.ensureInstance(instanceName, serviceType)
			for _, txt := range body.TXT {
				if txt != "" {
					instance.TXT.Add(txt)
				}
			}
			instance.addTTL(ttl)
			instance.SourceIPs.Add(packet.Source)
		case *dnsmessage.AResource:
			addr := netip.AddrFrom4(body.A).Unmap()
			host := d.ensureHost(name)
			host.IPv4.Add(addr)
			host.addTTL(ttl)
		case *dnsmessage.AAAAResource:
			addr := netip.AddrFrom16(body.AAAA).Unmap()
			host := d.ensureHost(name)
			host.IPv6.Add(addr)
			host.addTTL(ttl)
		}
	}
	return newServiceTypes
}

func (d *discoveryState) addServiceType(serviceType string) {
	if serviceType == "" {
		return
	}
	d.ServiceTypes.Add(serviceType)
	if _, ok := d.InstancesByType[serviceType]; !ok {
		set := newOrderedSet()
		d.InstancesByType[serviceType] = &set
	}
}

func (d *discoveryState) addInstance(serviceType, fqdn string, ttl uint32, source netip.Addr) {
	instance := d.ensureInstance(fqdn, serviceType)
	instance.addTTL(ttl)
	instance.SourceIPs.Add(source)

	set, ok := d.InstancesByType[serviceType]
	if !ok {
		newSet := newOrderedSet()
		set = &newSet
		d.InstancesByType[serviceType] = set
	}
	set.Add(fqdn)
}

func (d *discoveryState) ensureInstance(fqdn, serviceType string) *instanceState {
	fqdn = normalizeDNSName(fqdn)
	serviceType = normalizeDNSName(serviceType)
	if serviceType == "" {
		serviceType = d.serviceTypeForInstance(fqdn)
	}
	if existing, ok := d.Instances[fqdn]; ok {
		if existing.ServiceType == "" && serviceType != "" {
			existing.ServiceType = serviceType
			existing.Name = instanceName(fqdn, serviceType)
			d.addServiceType(serviceType)
			d.InstancesByType[serviceType].Add(fqdn)
		}
		return existing
	}

	instance := &instanceState{
		FQDN:        fqdn,
		ServiceType: serviceType,
		Name:        instanceName(fqdn, serviceType),
		TXT:         newOrderedSet(),
		SourceIPs:   newOrderedAddrSet(),
	}
	d.Instances[fqdn] = instance
	if serviceType != "" {
		d.addServiceType(serviceType)
		d.InstancesByType[serviceType].Add(fqdn)
	}
	return instance
}

func (d *discoveryState) ensureHost(name string) *hostState {
	name = normalizeDNSName(name)
	if existing, ok := d.Hosts[name]; ok {
		return existing
	}
	host := &hostState{
		Name:    name,
		IPv4:    newOrderedAddrSet(),
		IPv6:    newOrderedAddrSet(),
		Sources: newOrderedAddrSet(),
	}
	d.Hosts[name] = host
	return host
}

func (d *discoveryState) serviceTypeForInstance(fqdn string) string {
	fqdn = normalizeDNSName(fqdn)
	if serviceType, ok := d.ServiceTypeByName[fqdn]; ok {
		return serviceType
	}
	for serviceType := range d.InstancesByType {
		if strings.HasSuffix(fqdn, "."+serviceType) {
			d.ServiceTypeByName[fqdn] = serviceType
			return serviceType
		}
	}
	if inferred := inferServiceType(fqdn); inferred != "" {
		d.ServiceTypeByName[fqdn] = inferred
		return inferred
	}
	return ""
}

func (i *instanceState) addTTL(ttl uint32) {
	if ttl == 0 {
		return
	}
	if i.TTL == 0 || ttl < i.TTL {
		i.TTL = ttl
	}
}

func (h *hostState) addTTL(ttl uint32) {
	if ttl == 0 {
		return
	}
	if h.TTL == 0 || ttl < h.TTL {
		h.TTL = ttl
	}
}

func (h *hostState) addAddress(addr netip.Addr) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return
	}
	if addr.Is4() {
		h.IPv4.Add(addr)
		return
	}
	h.IPv6.Add(addr)
}

type parsedResource struct {
	Header dnsmessage.ResourceHeader
	Body   dnsmessage.ResourceBody
}

func parseResources(msg []byte) ([]parsedResource, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(msg); err != nil {
		return nil, err
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var resources []parsedResource
	readSection := func(read func() (dnsmessage.Resource, error)) error {
		for {
			resource, err := read()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				return nil
			}
			if err != nil {
				return err
			}
			resources = append(resources, parsedResource{Header: resource.Header, Body: resource.Body})
		}
	}

	if err := readSection(parser.Answer); err != nil {
		return nil, err
	}
	if err := readSection(parser.Authority); err != nil {
		return nil, err
	}
	if err := readSection(parser.Additional); err != nil {
		return nil, err
	}
	return resources, nil
}

type serviceOutput struct {
	ServiceType string
	Proto       string
	Service     string
	Name        string
	Port        uint16
	HasPort     bool
	Hostname    string
	IPv4        []netip.Addr
	IPv6        []netip.Addr
	TTL         uint32
	TXT         []string
}

func formatDiscovery(discovery *discoveryState, ipFilter ipFilter, portFilter portFilter) string {
	entries := buildServiceOutputs(discovery, ipFilter, portFilter)
	var b strings.Builder
	b.WriteString("services:\n")
	for _, entry := range entries {
		if entry.HasPort {
			fmt.Fprintf(&b, "%d/%s %s:\n", entry.Port, entry.Proto, entry.Service)
		} else {
			fmt.Fprintf(&b, "%s:\n", entry.Service)
		}
		fmt.Fprintf(&b, "Name=%s\n", entry.Name)
		if len(entry.IPv4) > 0 {
			fmt.Fprintf(&b, "IPv4=%s\n", joinAddrs(entry.IPv4))
		}
		if len(entry.IPv6) > 0 {
			fmt.Fprintf(&b, "IPv6=%s\n", joinAddrs(entry.IPv6))
		}
		if entry.Hostname != "" {
			fmt.Fprintf(&b, "Hostname=%s\n", entry.Hostname)
		}
		if entry.TTL > 0 {
			fmt.Fprintf(&b, "TTL=%d\n", entry.TTL)
		}
		for _, txt := range entry.TXT {
			b.WriteString(txt)
			b.WriteByte('\n')
		}
	}

	b.WriteString("answers:\n")
	b.WriteString("PTR:\n")
	for _, serviceType := range answerServiceTypes(discovery, entries) {
		b.WriteString(serviceType)
		b.WriteByte('\n')
	}
	return b.String()
}

func buildServiceOutputs(discovery *discoveryState, ipFilter ipFilter, portFilter portFilter) []serviceOutput {
	var entries []serviceOutput
	seen := map[string]bool{}
	orderedServiceTypes := discovery.ServiceTypes.Values()

	for _, serviceType := range orderedServiceTypes {
		set := discovery.InstancesByType[serviceType]
		if set == nil {
			continue
		}
		for _, fqdn := range set.Values() {
			instance := discovery.Instances[fqdn]
			if instance == nil || seen[instance.FQDN] {
				continue
			}
			seen[instance.FQDN] = true

			output, ok := buildServiceOutput(discovery, instance, ipFilter, portFilter)
			if ok {
				entries = append(entries, output)
			}
		}
	}

	for _, instance := range discovery.Instances {
		if seen[instance.FQDN] {
			continue
		}
		output, ok := buildServiceOutput(discovery, instance, ipFilter, portFilter)
		if ok {
			entries = append(entries, output)
		}
	}

	sort.SliceStable(entries, func(i, j int) bool {
		left := entries[i]
		right := entries[j]
		leftTypeIdx := discovery.ServiceTypes.Index(left.ServiceType)
		rightTypeIdx := discovery.ServiceTypes.Index(right.ServiceType)
		if leftTypeIdx != rightTypeIdx {
			return leftTypeIdx < rightTypeIdx
		}
		if left.HasPort != right.HasPort {
			return !left.HasPort
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Service != right.Service {
			return left.Service < right.Service
		}
		return left.Name < right.Name
	})
	return entries
}

func buildServiceOutput(discovery *discoveryState, instance *instanceState, ipFilter ipFilter, portFilter portFilter) (serviceOutput, bool) {
	serviceType := instance.ServiceType
	proto, service := splitServiceType(serviceType)
	if service == "" {
		service = serviceType
	}

	hostname := instance.Target
	if hostname == "" {
		hostname = inferHostname(discovery, instance)
	}
	host := discovery.Hosts[hostname]

	ipv4, ipv6 := collectEntryAddrs(instance, host)
	if !anyAddrMatches(ipFilter, ipv4, ipv6) {
		return serviceOutput{}, false
	}
	if instance.HasSRV && !portFilter.Contains(instance.Port) {
		return serviceOutput{}, false
	}

	ttl := instance.TTL
	if ttl == 0 && host != nil {
		ttl = host.TTL
	}
	return serviceOutput{
		ServiceType: serviceType,
		Proto:       proto,
		Service:     service,
		Name:        instance.Name,
		Port:        instance.Port,
		HasPort:     instance.HasSRV,
		Hostname:    hostname,
		IPv4:        ipv4,
		IPv6:        ipv6,
		TTL:         ttl,
		TXT:         formatTXT(instance.TXT.Values()),
	}, true
}

func collectEntryAddrs(instance *instanceState, host *hostState) ([]netip.Addr, []netip.Addr) {
	ipv4Set := newOrderedAddrSet()
	ipv6Set := newOrderedAddrSet()

	if host != nil {
		for _, addr := range host.IPv4.Values() {
			ipv4Set.Add(addr)
		}
		for _, addr := range host.IPv6.Values() {
			ipv6Set.Add(addr)
		}
		for _, addr := range host.Sources.Values() {
			if addr.Is4() {
				ipv4Set.Add(addr)
			} else if addr.Is6() {
				ipv6Set.Add(addr)
			}
		}
	}

	for _, addr := range instance.SourceIPs.Values() {
		if addr.Is4() {
			ipv4Set.Add(addr)
		} else if addr.Is6() {
			ipv6Set.Add(addr)
		}
	}

	return ipv4Set.Values(), ipv6Set.Values()
}

func inferHostname(discovery *discoveryState, instance *instanceState) string {
	base := baseInstanceName(instance.Name)
	if base != "" {
		candidate := normalizeDNSName(base + ".local")
		if _, ok := discovery.Hosts[candidate]; ok {
			return candidate
		}
		for _, other := range discovery.Instances {
			if other == instance || other.Target == "" {
				continue
			}
			if baseInstanceName(other.Name) == base {
				return other.Target
			}
		}
		return candidate
	}
	return ""
}

func answerServiceTypes(discovery *discoveryState, entries []serviceOutput) []string {
	answers := newOrderedSet()
	for _, serviceType := range discovery.ServiceTypes.Values() {
		answers.Add(serviceType)
	}
	for _, entry := range entries {
		answers.Add(entry.ServiceType)
	}
	return answers.Values()
}

func anyAddrMatches(filter ipFilter, groups ...[]netip.Addr) bool {
	for _, group := range groups {
		for _, addr := range group {
			if filter.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func formatTXT(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	if len(values) == 1 {
		return values
	}
	allKeyValues := true
	for _, value := range values {
		if !strings.Contains(value, "=") {
			allKeyValues = false
			break
		}
	}
	if allKeyValues {
		return []string{strings.Join(values, ",")}
	}
	return values
}

type orderedSet struct {
	items []string
	seen  map[string]bool
	index map[string]int
}

func newOrderedSet() orderedSet {
	return orderedSet{
		seen:  map[string]bool{},
		index: map[string]int{},
	}
}

func (s *orderedSet) Add(value string) {
	if value == "" || s.seen[value] {
		return
	}
	s.seen[value] = true
	s.index[value] = len(s.items)
	s.items = append(s.items, value)
}

func (s orderedSet) Has(value string) bool {
	return s.seen[value]
}

func (s orderedSet) Values() []string {
	out := make([]string, len(s.items))
	copy(out, s.items)
	return out
}

func (s orderedSet) Index(value string) int {
	if idx, ok := s.index[value]; ok {
		return idx
	}
	return int(^uint(0) >> 1)
}

type orderedAddrSet struct {
	items []netip.Addr
	seen  map[netip.Addr]bool
}

func newOrderedAddrSet() orderedAddrSet {
	return orderedAddrSet{seen: map[netip.Addr]bool{}}
}

func (s *orderedAddrSet) Add(addr netip.Addr) {
	addr = addr.Unmap()
	if !addr.IsValid() || s.seen[addr] {
		return
	}
	s.seen[addr] = true
	s.items = append(s.items, addr)
}

func (s orderedAddrSet) Values() []netip.Addr {
	out := make([]netip.Addr, len(s.items))
	copy(out, s.items)
	return out
}

func splitServiceType(serviceType string) (proto string, service string) {
	labels := strings.Split(normalizeDNSName(serviceType), ".")
	if len(labels) < 3 {
		return "", strings.TrimPrefix(serviceType, "_")
	}
	service = strings.TrimPrefix(labels[0], "_")
	proto = strings.TrimPrefix(labels[1], "_")
	return proto, service
}

func instanceName(fqdn, serviceType string) string {
	fqdn = normalizeDNSName(fqdn)
	serviceType = normalizeDNSName(serviceType)
	if serviceType != "" && strings.HasSuffix(fqdn, "."+serviceType) {
		return strings.TrimSuffix(fqdn, "."+serviceType)
	}
	if idx := strings.Index(fqdn, "._"); idx >= 0 {
		return fqdn[:idx]
	}
	return fqdn
}

func inferServiceType(fqdn string) string {
	labels := strings.Split(normalizeDNSName(fqdn), ".")
	for i := 0; i+2 < len(labels); i++ {
		if strings.HasPrefix(labels[i], "_") && strings.HasPrefix(labels[i+1], "_") && labels[len(labels)-1] == "local" {
			return strings.Join(labels[i:], ".")
		}
	}
	return ""
}

func isServiceType(name string) bool {
	labels := strings.Split(normalizeDNSName(name), ".")
	return len(labels) >= 3 && strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_") && labels[len(labels)-1] == "local"
}

func baseInstanceName(name string) string {
	name = strings.TrimSpace(name)
	if idx := strings.Index(name, "("); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".")
}

func ensureTrailingDot(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func splitCSV(input string) []string {
	var out []string
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, ",")
}

func compareAddr(left, right netip.Addr) int {
	left = left.Unmap()
	right = right.Unmap()
	if left.Less(right) {
		return -1
	}
	if right.Less(left) {
		return 1
	}
	return 0
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func joinErrors(errs []error) string {
	var parts []string
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	if len(parts) == 0 {
		return "unknown error"
	}
	return strings.Join(parts, "; ")
}
