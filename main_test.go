package main

import (
	"net/netip"
	"testing"
)

func TestFormatDiscoveryMatchesSampleShape(t *testing.T) {
	discovery := newDiscoveryState()
	serviceTypes := []string{
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"_afpovertcp._tcp.local",
	}
	for _, serviceType := range serviceTypes {
		discovery.addServiceType(serviceType)
	}

	host := discovery.ensureHost("slw-nas.local")
	host.IPv4.Add(mustAddr(t, "192.168.1.10"))
	host.IPv6.Add(mustAddr(t, "fe80::265e:beff:fe69:a313"))
	host.TTL = 10

	addSRVInstance(t, discovery, "_workstation._tcp.local", "slw-nas [24:5e:be:69:a3:13]", 9, "slw-nas.local", 10)
	http := addSRVInstance(t, discovery, "_http._tcp.local", "slw-nas", 5000, "slw-nas.local", 10)
	http.TXT.Add("path=/")
	addSRVInstance(t, discovery, "_smb._tcp.local", "slw-nas", 445, "slw-nas.local", 10)
	qdiscover := addSRVInstance(t, discovery, "_qdiscover._tcp.local", "slw-nas", 5000, "slw-nas.local", 10)
	qdiscover.TXT.Add("accessType=https")
	qdiscover.TXT.Add("accessPort=86")
	qdiscover.TXT.Add("model=TS-X64")
	qdiscover.TXT.Add("displayModel=TS-464C")
	qdiscover.TXT.Add("fwVer=5.2.9")
	qdiscover.TXT.Add("fwBuildNum=20260214")
	deviceInfo := discovery.ensureInstance("slw-nas(AFP)._device-info._tcp.local", "_device-info._tcp.local")
	deviceInfo.TTL = 10
	deviceInfo.TXT.Add("model=Xserve")
	addSRVInstance(t, discovery, "_afpovertcp._tcp.local", "slw-nas(AFP)", 548, "slw-nas.local", 10)

	filter, err := parseIPFilter("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := parsePortFilter("1-65535")
	if err != nil {
		t.Fatal(err)
	}

	got := formatDiscovery(discovery, filter, ports)
	want := `services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
445/tcp smb:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_smb._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
_afpovertcp._tcp.local
`
	if got != want {
		t.Fatalf("unexpected output\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestFiltersAcceptCIDRRangeAndPortList(t *testing.T) {
	filter, err := parseIPFilter("192.168.1.0/30,10.0.0.5-10.0.0.8,fe80::/64")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.168.1.1", "10.0.0.7", "fe80::1"} {
		if !filter.Contains(mustAddr(t, ip)) {
			t.Fatalf("expected %s to match", ip)
		}
	}
	if filter.Contains(mustAddr(t, "10.0.0.9")) {
		t.Fatal("did not expect 10.0.0.9 to match")
	}

	ports, err := parsePortFilter("80,443,5000-5002")
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{80, 443, 5001} {
		if !ports.Contains(port) {
			t.Fatalf("expected port %d to match", port)
		}
	}
	if ports.Contains(22) {
		t.Fatal("did not expect port 22 to match")
	}
}

func addSRVInstance(t *testing.T, discovery *discoveryState, serviceType, name string, port uint16, target string, ttl uint32) *instanceState {
	t.Helper()
	fqdn := name + "." + serviceType
	instance := discovery.ensureInstance(fqdn, serviceType)
	instance.HasSRV = true
	instance.Port = port
	instance.Target = target
	instance.TTL = ttl
	return instance
}

func mustAddr(t *testing.T, input string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(input)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
