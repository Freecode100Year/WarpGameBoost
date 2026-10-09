//go:build windows

package main

import (
	"bufio"
	_ "embed"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

//go:embed wintun.dll
var wintunDLL []byte

const adapterName = "WarpGameBoost"

var (
	allowV4  = flag.Bool("ipv4", false, "也使用 IPv4 入口（默认只用 IPv6 入口）")
	count    = flag.Int("count", 200, "每次优选测试的入口数量")
	selftest = flag.Bool("selftest", false, "连接、验证后立即退出（用于自动测试）")
)

// physIndex is the interface the tunnel's own UDP packets leave through; probes
// are bound to it too, so a rescan while the tunnel is up measures the real path.
var physIndex4, physIndex6 uint32

func main() {
	windows.SetConsoleOutputCP(65001)
	flag.Parse()
	if !windows.GetCurrentProcessToken().IsElevated() {
		elevate()
		return
	}
	code := run()
	if !*selftest {
		fmt.Println("\n按回车键退出…")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

// elevate restarts this program as administrator: a virtual network adapter and
// routes cannot be created otherwise.
func elevate() {
	exe, _ := os.Executable()
	args := strings.Join(os.Args[1:], " ")
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	if err := windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL); err != nil {
		fmt.Println("需要管理员权限才能创建虚拟网卡：", err)
		time.Sleep(5 * time.Second)
	}
}

func run() int {
	fmt.Println("WarpGameBoost — Cloudflare WARP 游戏加速（IPv6 入口 IP 优选）")
	fmt.Println()
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "WarpGameBoost")
	acctPath := filepath.Join(dir, "account.json")
	acct, err := loadAccount(acctPath)
	if err != nil {
		fmt.Println("正在注册免费 WARP 账号…")
		if acct, err = register(); err != nil {
			fmt.Println("注册失败：", err)
			return 1
		}
		saveAccount(acctPath, acct)
	}

	physIndex6 = defaultInterface(winipcfg.AddressFamily(windows.AF_INET6), 0)
	if *allowV4 {
		physIndex4 = defaultInterface(winipcfg.AddressFamily(windows.AF_INET), 0)
	}
	if physIndex6 == 0 && !*allowV4 {
		fmt.Println("本机没有 IPv6 网络。本程序默认只走 IPv6 入口；")
		fmt.Println("可以换有 IPv6 的网络，或加参数 -ipv4 同时使用 IPv4 入口。")
		return 1
	}

	results := optimize(acct, "")
	if len(results) == 0 {
		fmt.Println("没有找到可用的 WARP 入口：所在网络可能封锁了 WARP。")
		return 1
	}
	acct.Best = results[0].Endpoint
	acct.BestRTTms = int(results[0].RTT.Milliseconds())
	acct.ScannedAt = time.Now()
	saveAccount(acctPath, acct)

	if err := installWintun(); err != nil {
		fmt.Println("无法写入 wintun.dll：", err)
		return 1
	}
	t, err := start(acct, results)
	if err != nil {
		fmt.Println("连接失败：", err)
		return 1
	}
	defer func() {
		t.dev.Close()
		fmt.Println("\n加速已关闭，网络已恢复。")
	}()

	trace := warpTrace()
	if !strings.Contains(trace, "warp=on") {
		fmt.Println("隧道已建立，但验证失败：", strings.TrimSpace(trace))
		return 1
	}
	fmt.Printf("\n✅ 加速已开启：本机全部网络（包括游戏）经 WARP 入口 %s\n", t.endpoint())
	fmt.Println("   现在可以打开游戏。关闭本窗口或按 Ctrl+C 结束加速；输入 r 回车重新优选。")
	fmt.Println()
	if *selftest {
		fmt.Println(strings.TrimSpace(trace))
		return 0
	}
	t.loop(acct, acctPath)
	return 0
}

func optimize(acct *Account, current string) []scored {
	fmt.Println("正在优选 WARP 入口（约 20 秒）…")
	results := scan(acct, *count, *allowV4, true, current)
	fmt.Printf("可用入口 %d 个，前五名：\n", len(results))
	fmt.Println("   入口                                        延迟    抖动   丢包")
	for i, r := range results {
		if i == 5 {
			break
		}
		fmt.Printf("   %-42s %4d ms %4d ms %3d%%\n", r.Endpoint, r.RTT.Milliseconds(), r.Jitter.Milliseconds(), r.Loss)
	}
	return results
}

type tunnel struct {
	dev  *device.Device
	bind conn.Bind
	luid winipcfg.LUID
	key  string
	mu   sync.Mutex
	ep   string
}

func (t *tunnel) endpoint() string { t.mu.Lock(); defer t.mu.Unlock(); return t.ep }

func installWintun() error {
	exe, _ := os.Executable()
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if b, err := os.ReadFile(path); err == nil && bytes.Equal(b, wintunDLL) {
		return nil
	}
	return os.WriteFile(path, wintunDLL, 0o644)
}

func start(acct *Account, results []scored) (*tunnel, error) {
	tdev, err := tun.CreateTUN(adapterName, 1280)
	if err != nil {
		return nil, err
	}
	t := &tunnel{luid: winipcfg.LUID(tdev.(*tun.NativeTun).LUID())}
	t.bind = conn.NewDefaultBind()
	t.dev = device.NewDevice(tdev, t.bind, device.NewLogger(device.LogLevelSilent, ""))
	priv, _ := base64.StdEncoding.DecodeString(acct.PrivateKey)
	peer, _ := base64.StdEncoding.DecodeString(acct.PeerKey)
	t.key = hex.EncodeToString(peer)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(priv), t.key, results[0].Endpoint)
	if err := t.dev.IpcSet(cfg); err != nil {
		t.dev.Close()
		return nil, err
	}
	t.ep = results[0].Endpoint
	if err := t.dev.Up(); err != nil {
		t.dev.Close()
		return nil, err
	}
	// The tunnel's own packets must leave through the real network, not loop
	// back into the routes added below.
	if b, ok := t.bind.(conn.BindSocketToInterface); ok {
		if physIndex6 != 0 {
			b.BindSocketToInterface6(physIndex6, false)
		}
		if physIndex4 != 0 {
			b.BindSocketToInterface4(physIndex4, false)
		}
	}
	// Try the best few endpoints until one completes a handshake.
	ok := false
	for i, r := range results {
		if i == 5 {
			break
		}
		if i > 0 && !t.roam(r.Endpoint) {
			continue
		}
		if t.waitHandshake(8 * time.Second) {
			ok = true
			break
		}
	}
	if !ok {
		t.dev.Close()
		return nil, fmt.Errorf("WARP 入口不回应握手")
	}
	if err := t.configure(acct); err != nil {
		t.dev.Close()
		return nil, err
	}
	return t, nil
}

// configure gives the adapter WARP's addresses and Cloudflare DNS and sends all
// traffic through it. Two half routes win over the default route without
// touching it, so closing the adapter restores the network exactly.
func (t *tunnel) configure(acct *Account) error {
	var addrs []netip.Prefix
	for _, s := range []string{acct.AddrV4, acct.AddrV6} {
		if a, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	if err := t.luid.SetIPAddresses(addrs); err != nil {
		return fmt.Errorf("设置地址：%w", err)
	}
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if iface, err := t.luid.IPInterface(fam); err == nil {
			iface.UseAutomaticMetric = false
			iface.Metric = 0
			iface.NLMTU = 1280
			iface.Set()
		}
	}
	t.luid.SetDNS(windows.AF_INET, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}, nil)
	t.luid.SetDNS(windows.AF_INET6, []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001")}, nil)
	routes := []*winipcfg.RouteData{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: netip.IPv4Unspecified()},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), NextHop: netip.IPv4Unspecified()},
		{Destination: netip.MustParsePrefix("::/1"), NextHop: netip.IPv6Unspecified()},
		{Destination: netip.MustParsePrefix("8000::/1"), NextHop: netip.IPv6Unspecified()},
	}
	if err := t.luid.SetRoutes(routes); err != nil {
		return fmt.Errorf("设置路由：%w", err)
	}
	return nil
}

func (t *tunnel) handshakeAge() time.Duration {
	s, err := t.dev.IpcGet()
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			sec, _ := strconv.ParseInt(v, 10, 64)
			if sec == 0 {
				return -1
			}
			return time.Since(time.Unix(sec, 0))
		}
	}
	return -1
}

func (t *tunnel) waitHandshake(limit time.Duration) bool {
	// Any packet into the tunnel starts a handshake; keepalive sends one at once.
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if age := t.handshakeAge(); age >= 0 && age < time.Minute {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// roam points the running tunnel at another endpoint. Re-adding the peer drops
// its old session so the next packet handshakes with the new endpoint at once.
func (t *tunnel) roam(endpoint string) bool {
	time.Sleep(40 * time.Millisecond) // keep the handshake timestamp newer than the probes'
	cfg := fmt.Sprintf("public_key=%s\nremove=true\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n", t.key, t.key, endpoint)
	if t.dev.IpcSet(cfg) != nil {
		return false
	}
	t.mu.Lock()
	t.ep = endpoint
	t.mu.Unlock()
	return true
}

// loop shows the live latency and switches entries when the current one fails.
func (t *tunnel) loop(acct *Account, acctPath string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	keys := make(chan string)
	go func() {
		r := bufio.NewReader(os.Stdin)
		for {
			s, err := r.ReadString('\n')
			if err != nil {
				return
			}
			keys <- strings.TrimSpace(strings.ToLower(s))
		}
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	fails := 0
	for {
		select {
		case <-sig:
			return
		case k := <-keys:
			if k == "q" {
				return
			}
			if k == "r" {
				t.reoptimize(acct, acctPath)
			}
		case <-tick.C:
			rtt, ok := tcpPing("1.1.1.1:443")
			age := t.handshakeAge()
			if ok {
				fails = 0
				fmt.Printf("\r[%s] 入口 %s · 经隧道到 Cloudflare %3d ms        ", time.Now().Format("15:04:05"), t.endpoint(), rtt.Milliseconds())
			} else {
				fails++
				fmt.Printf("\r[%s] 隧道无响应（%d）…                          ", time.Now().Format("15:04:05"), fails)
			}
			if fails >= 3 || age > 3*time.Minute {
				fmt.Println("\n当前入口失效，重新优选…")
				t.reoptimize(acct, acctPath)
				fails = 0
			}
		}
	}
}

func (t *tunnel) reoptimize(acct *Account, acctPath string) {
	fmt.Println()
	physIndex6 = defaultInterface(windows.AF_INET6, t.luid)
	if *allowV4 {
		physIndex4 = defaultInterface(windows.AF_INET, t.luid)
	}
	results := optimize(acct, t.endpoint())
	if len(results) == 0 {
		fmt.Println("没有找到可用入口，保持当前入口。")
		return
	}
	if results[0].Endpoint != t.endpoint() && t.roam(results[0].Endpoint) {
		t.waitHandshake(8 * time.Second)
		fmt.Println("已切换到", results[0].Endpoint)
	} else {
		fmt.Println("当前入口仍是最好的。")
	}
	acct.Best, acct.BestRTTms, acct.ScannedAt = results[0].Endpoint, int(results[0].RTT.Milliseconds()), time.Now()
	saveAccount(acctPath, acct)
}

func tcpPing(addr string) (time.Duration, bool) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return 0, false
	}
	c.Close()
	return time.Since(start), true
}

func warpTrace() string {
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 3; i++ {
		resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return string(b)
		}
		time.Sleep(2 * time.Second)
	}
	return ""
}

// defaultInterface returns the index of the interface holding the preferred
// default route of a family, ignoring our own adapter. 0 means none.
func defaultInterface(family winipcfg.AddressFamily, skip winipcfg.LUID) uint32 {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0
	}
	best, bestMetric := uint32(0), uint32(^uint32(0))
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == skip {
			continue
		}
		iface, err := r.InterfaceLUID.IPInterface(family)
		if err != nil || !iface.Connected {
			continue
		}
		if m := r.Metric + iface.Metric; m < bestMetric {
			best, bestMetric = r.InterfaceIndex, m
		}
	}
	return best
}

// dialOutside opens a UDP socket to a WARP endpoint that leaves through the
// physical interface even while the tunnel's routes are in place.
func dialOutside(endpoint string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: time.Second, Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		c.Control(func(fd uintptr) {
			const unicastIF = 31 // IP_UNICAST_IF / IPV6_UNICAST_IF
			if ap.Addr().Is6() && physIndex6 != 0 {
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, unicastIF, int(physIndex6))
			} else if ap.Addr().Is4() && physIndex4 != 0 {
				// IPv4 takes the index in network byte order.
				var be [4]byte
				be[0], be[1], be[2], be[3] = byte(physIndex4>>24), byte(physIndex4>>16), byte(physIndex4>>8), byte(physIndex4)
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, unicastIF, int(uint32(be[3])<<24|uint32(be[2])<<16|uint32(be[1])<<8|uint32(be[0])))
			}
		})
		return serr
	}}
	return d.Dial("udp", endpoint)
}
