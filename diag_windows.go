package main

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	iphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	icmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	icmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	icmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

type ipOptionInformation struct {
	TTL, TOS, Flags, OptionsSize uint8
	OptionsData                  uintptr
}

type icmpEchoReply struct {
	Address       [4]byte
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

const ipTTLExpiredTransit = 11013

// ping sends one ICMP echo with the given TTL. It returns who answered (the
// target, or the router where the TTL ran out), and the round trip.
func ping(h uintptr, dst netip.Addr, ttl uint8, timeout time.Duration) (from netip.Addr, rtt time.Duration, ok bool) {
	payload := []byte("WarpGameBoost diag")
	reply := make([]byte, unsafe.Sizeof(icmpEchoReply{})+uintptr(len(payload))+64)
	opt := ipOptionInformation{TTL: ttl}
	a := dst.As4()
	start := time.Now()
	n, _, _ := icmpSendEcho.Call(h, uintptr(*(*uint32)(unsafe.Pointer(&a[0]))),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	elapsed := time.Since(start)
	if n == 0 {
		return netip.Addr{}, 0, false
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if r.Status != 0 && r.Status != ipTTLExpiredTransit {
		return netip.Addr{}, 0, false
	}
	// The API reports whole milliseconds; the wall clock is finer for hops
	// under a millisecond and costs at most a scheduler tick on top.
	return netip.AddrFrom4(r.Address), min(elapsed, time.Duration(r.RoundTripTime+1)*time.Millisecond), true
}

func publicHop(a netip.Addr) bool {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !cgnat.Contains(a)
}

// defaultGateway4 returns the IPv4 next hop of the preferred default route and
// whether that interface is Wi-Fi.
func defaultGateway4() (netip.Addr, bool) {
	idx := defaultInterface(winipcfg.AddressFamily(windows.AF_INET), 0)
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil || idx == 0 {
		return netip.Addr{}, false
	}
	for i := range rows {
		r := &rows[i]
		if r.InterfaceIndex == idx && r.DestinationPrefix.PrefixLength == 0 {
			gw := r.NextHop.Addr()
			wifi := false
			if row, err := r.InterfaceLUID.Interface(); err == nil {
				wifi = row.Type == winipcfg.IfTypeIEEE80211
			}
			return gw, wifi
		}
	}
	return netip.Addr{}, false
}

// phoneHotspots are the router addresses iPhones and Android phones use when
// sharing their mobile connection.
var phoneHotspots = []netip.Addr{netip.MustParseAddr("172.20.10.1"), netip.MustParseAddr("192.168.43.1")}

// diagnose measures the two legs a game's packets cross before they leave
// the ISP — this computer to the router, and on to the ISP's first router —
// before the tunnel is up, and says which one is unstable.
func diagnose() {
	const samples, interval = 60, 250 * time.Millisecond
	fmt.Printf("网络诊断（约 %d 秒，加 -diag=false 可跳过）…\n", samples*int(interval)/int(time.Second)+3)
	h, _, _ := icmpCreateFile.Call()
	if h == uintptr(windows.InvalidHandle) {
		fmt.Println("无法诊断：ICMP 不可用。")
		return
	}
	defer icmpCloseHandle.Call(h)

	gwAddr, wifi := defaultGateway4()
	var gw, isp *series
	var ispAddr netip.Addr
	if gwAddr.IsValid() && !gwAddr.IsUnspecified() {
		gw = &series{name: "电脑 → 路由器 " + gwAddr.String()}
	}
	// Traceroute towards Cloudflare's resolver to find where the ISP starts.
	for ttl := uint8(1); ttl <= 8; ttl++ {
		if from, _, ok := ping(h, netip.MustParseAddr("1.1.1.1"), ttl, time.Second); ok && publicHop(from) {
			if from != netip.MustParseAddr("1.1.1.1") {
				isp, ispAddr = &series{name: "→ 运营商 " + from.String()}, from
			}
			break
		}
	}

	var wg sync.WaitGroup
	icmpSeries := func(s *series, dst netip.Addr) {
		defer wg.Done()
		h, _, _ := icmpCreateFile.Call()
		defer icmpCloseHandle.Call(h)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for i := 0; i < samples; i++ {
			s.sent++
			if _, rtt, ok := ping(h, dst, 64, time.Second); ok {
				s.rtts = append(s.rtts, rtt)
			}
			<-tick.C
		}
	}
	if gw != nil {
		wg.Add(1)
		go icmpSeries(gw, gwAddr)
	}
	if isp != nil {
		wg.Add(1)
		go icmpSeries(isp, ispAddr)
	}
	wg.Wait()

	fmt.Println()
	fmt.Print(report(gw, isp, wifi, slices.Contains(phoneHotspots, gwAddr)))
	fmt.Println()
}
