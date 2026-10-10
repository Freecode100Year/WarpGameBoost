package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	local  = netip.MustParseAddr("172.16.0.2")
	remote = netip.MustParseAddr("1.1.1.1")
	dns    = netip.MustParseAddr("8.8.8.8")
)

func allowDNS(a netip.Addr) bool { return a == dns }

func packet(proto byte, dst netip.Addr, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	ipHeader(b, proto, local, dst)
	copy(b[20:], payload)
	return b
}

func syn(seq uint32) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:2], 50000)
	binary.BigEndian.PutUint16(t[2:4], 443)
	binary.BigEndian.PutUint32(t[4:8], seq)
	t[12] = 5 << 4
	t[13] = 0x02
	binary.BigEndian.PutUint16(t[16:18], transportChecksum(6, local, remote, t))
	return t
}

func TestIPv6AndAllowedPass(t *testing.T) {
	v6 := make([]byte, 40)
	v6[0] = 6 << 4
	if drop, _ := rejectV4(v6, allowDNS); drop {
		t.Fatal("IPv6 dropped")
	}
	if drop, _ := rejectV4(packet(17, dns, make([]byte, 8)), allowDNS); drop {
		t.Fatal("DNS server dropped")
	}
}

func TestTCPSynGetsReset(t *testing.T) {
	drop, r := rejectV4(packet(6, remote, syn(1000)), allowDNS)
	if !drop || len(r) != 40 {
		t.Fatalf("drop=%v reply=%d bytes", drop, len(r))
	}
	if checksum(r[:20], 0) != 0 {
		t.Error("bad IP checksum")
	}
	if netip.AddrFrom4([4]byte(r[12:16])) != remote || netip.AddrFrom4([4]byte(r[16:20])) != local {
		t.Error("addresses not swapped")
	}
	tcp := r[20:]
	if binary.BigEndian.Uint16(tcp[0:2]) != 443 || binary.BigEndian.Uint16(tcp[2:4]) != 50000 {
		t.Error("ports not swapped")
	}
	if tcp[13] != 0x14 || binary.BigEndian.Uint32(tcp[8:12]) != 1001 {
		t.Errorf("flags %#x ack %d, want RST|ACK 1001", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	if transportChecksum(6, remote, local, tcp) != 0 {
		t.Error("bad TCP checksum")
	}
}

func TestResetIsNotAnswered(t *testing.T) {
	s := syn(1)
	s[13] = 0x04
	if drop, r := rejectV4(packet(6, remote, s), allowDNS); !drop || r != nil {
		t.Fatal("a reset must be dropped silently")
	}
}

func TestUDPGetsPortUnreachable(t *testing.T) {
	p := packet(17, remote, make([]byte, 30))
	drop, r := rejectV4(p, allowDNS)
	if !drop || r == nil {
		t.Fatal("no reply")
	}
	if r[9] != 1 || r[20] != 3 || r[21] != 3 {
		t.Errorf("proto %d type %d code %d", r[9], r[20], r[21])
	}
	if checksum(r[20:], 0) != 0 || checksum(r[:20], 0) != 0 {
		t.Error("bad checksum")
	}
	if len(r) != 20+8+28 {
		t.Errorf("reply %d bytes", len(r))
	}
}

func TestMulticastAndICMPErrorsSilent(t *testing.T) {
	if drop, r := rejectV4(packet(17, netip.MustParseAddr("239.255.255.250"), make([]byte, 8)), allowDNS); !drop || r != nil {
		t.Error("multicast must be dropped silently")
	}
	icmpErr := make([]byte, 8)
	icmpErr[0] = 3
	if drop, r := rejectV4(packet(1, remote, icmpErr), allowDNS); !drop || r != nil {
		t.Error("ICMP error must be dropped silently")
	}
	echo := make([]byte, 8)
	echo[0] = 8
	if drop, r := rejectV4(packet(1, remote, echo), allowDNS); !drop || r == nil || r[21] != 1 {
		t.Error("ping must get host unreachable")
	}
}

var (
	local6  = netip.MustParseAddr("2606:4700:110:8000::1")
	remote6 = netip.MustParseAddr("2606:4700:4700::1111")
)

func packet6(next byte, dst netip.Addr, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	ip6Header(b, next, local6, dst)
	copy(b[40:], payload)
	return b
}

func TestV6TCPSynGetsReset(t *testing.T) {
	s := syn(7)
	drop, r := rejectV6(packet6(6, remote6, s), allowDNS)
	if !drop || len(r) != 60 {
		t.Fatalf("drop=%v reply=%d bytes", drop, len(r))
	}
	if netip.AddrFrom16([16]byte(r[8:24])) != remote6 || netip.AddrFrom16([16]byte(r[24:40])) != local6 {
		t.Error("addresses not swapped")
	}
	tcp := r[40:]
	if tcp[13] != 0x14 || binary.BigEndian.Uint32(tcp[8:12]) != 8 {
		t.Errorf("flags %#x ack %d", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	if checksum6(6, remote6, local6, tcp) != 0 {
		t.Error("bad TCP checksum")
	}
}

func TestV6UDPAndSilentCases(t *testing.T) {
	drop, r := rejectV6(packet6(17, remote6, make([]byte, 16)), allowDNS)
	if !drop || r == nil || r[6] != 58 || r[40] != 1 || r[41] != 4 {
		t.Fatalf("UDP reply %v", r)
	}
	if checksum6(58, remote6, local6, r[40:]) != 0 {
		t.Error("bad ICMPv6 checksum")
	}
	ns := make([]byte, 24)
	ns[0] = 135
	if drop, r := rejectV6(packet6(58, remote6, ns), allowDNS); !drop || r != nil {
		t.Error("neighbour solicitation must be dropped silently")
	}
	if drop, r := rejectV6(packet6(17, netip.MustParseAddr("ff02::fb"), make([]byte, 8)), allowDNS); !drop || r != nil {
		t.Error("multicast must be dropped silently")
	}
	if drop, _ := rejectV6(packet(6, remote, syn(1)), allowDNS); drop {
		t.Error("IPv4 must pass")
	}
	if drop, _ := rejectV6(packet6(17, netip.MustParseAddr("2606:4700:4700::1112"), make([]byte, 8)), func(a netip.Addr) bool { return a == netip.MustParseAddr("2606:4700:4700::1112") }); drop {
		t.Error("allowed DNS must pass")
	}
}
