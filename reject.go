package main

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// v4Reject sits between Windows and WireGuard when the exit is IPv6 only. IPv4
// is still routed into the tunnel so nothing goes around it, but instead of
// vanishing (which leaves programs waiting out their timeouts before trying
// IPv6) each IPv4 packet is answered at once: TCP with a reset, everything else
// with ICMP unreachable. Programs see "refused" and move on to IPv6.
type v4Reject struct {
	tun.Device
	allow atomic.Pointer[[]netip.Addr] // IPv4 destinations let through (the system's DNS servers)
}

func (r *v4Reject) setAllowed(a []netip.Addr) { r.allow.Store(&a) }

func (r *v4Reject) allowed(dst netip.Addr) bool {
	if p := r.allow.Load(); p != nil {
		for _, a := range *p {
			if a == dst {
				return true
			}
		}
	}
	return false
}

func (r *v4Reject) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		n, err := r.Device.Read(bufs, sizes, offset)
		k := 0
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			if drop, reply := rejectV4(pkt, r.allowed); drop {
				if reply != nil {
					out := make([]byte, offset+len(reply))
					copy(out[offset:], reply)
					r.Device.Write([][]byte{out}, offset)
				}
				continue
			}
			// WireGuard pairs buffers with its own bookkeeping by index, so
			// close the gap by copying rather than swapping slices.
			if k != i {
				copy(bufs[k][offset:], pkt)
				sizes[k] = sizes[i]
			}
			k++
		}
		if k > 0 || err != nil || n == 0 {
			return k, err
		}
	}
}

// rejectV4 decides what happens to a packet leaving Windows. IPv6 and allowed
// IPv4 pass; other IPv4 is dropped, with reply (when non-nil) to be handed back
// to Windows.
func rejectV4(pkt []byte, allow func(netip.Addr) bool) (drop bool, reply []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false, nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return true, nil
	}
	pkt = pkt[:total]
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if allow(dst) {
		return false, nil
	}
	if dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true, nil
	}
	fragment := binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0
	switch proto := pkt[9]; {
	case fragment:
		return true, nil
	case proto == 6:
		return true, tcpReset(pkt[ihl:], src, dst)
	case proto == 1 && len(pkt) > ihl && pkt[ihl] != 8:
		return true, nil // never answer ICMP errors or replies
	case proto == 17:
		return true, icmpUnreachable(pkt, dst, src, 3) // port unreachable
	default:
		return true, icmpUnreachable(pkt, dst, src, 1) // host unreachable
	}
}

// tcpReset answers a TCP segment from src to dst with a reset from dst, as a
// host with nothing listening would (RFC 9293 3.10.7.1).
func tcpReset(seg []byte, src, dst netip.Addr) []byte {
	if len(seg) < 20 {
		return nil
	}
	flags := seg[13]
	if flags&0x04 != 0 { // never answer a reset
		return nil
	}
	off := int(seg[12]>>4) * 4
	if off < 20 || off > len(seg) {
		return nil
	}
	b := make([]byte, 40)
	ipHeader(b, 6, dst, src)
	t := b[20:]
	copy(t[0:2], seg[2:4]) // swap ports
	copy(t[2:4], seg[0:2])
	t[12] = 5 << 4
	if flags&0x10 != 0 { // ACK set: the reset takes its sequence from the ack
		copy(t[4:8], seg[8:12])
		t[13] = 0x04
	} else {
		n := uint32(len(seg) - off)
		if flags&0x02 != 0 {
			n++
		}
		if flags&0x01 != 0 {
			n++
		}
		binary.BigEndian.PutUint32(t[8:12], binary.BigEndian.Uint32(seg[4:8])+n)
		t[13] = 0x14
	}
	binary.BigEndian.PutUint16(t[16:18], transportChecksum(6, dst, src, t))
	return b
}

// icmpUnreachable builds ICMP destination unreachable (type 3) from `from` to
// `to`, quoting the offending packet's header and first 8 bytes of payload.
func icmpUnreachable(orig []byte, from, to netip.Addr, code byte) []byte {
	ihl := int(orig[0]&0x0f) * 4
	quote := orig[:min(len(orig), ihl+8)]
	b := make([]byte, 20+8+len(quote))
	ipHeader(b, 1, from, to)
	m := b[20:]
	m[0], m[1] = 3, code
	copy(m[8:], quote)
	binary.BigEndian.PutUint16(m[2:4], checksum(m, 0))
	return b
}

func ipHeader(b []byte, proto byte, src, dst netip.Addr) {
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:20], 0))
}

func transportChecksum(proto byte, src, dst netip.Addr, seg []byte) uint16 {
	s, d := src.As4(), dst.As4()
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(s[0:2])) + uint32(binary.BigEndian.Uint16(s[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d[0:2])) + uint32(binary.BigEndian.Uint16(d[2:4]))
	sum += uint32(proto) + uint32(len(seg))
	return checksum(seg, sum)
}

func checksum(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
