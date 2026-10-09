//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
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
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

//go:embed wintun.dll
var wintunDLL []byte

const adapterName = "WarpGameBoost"

// version is set at build time: -ldflags "-X main.version=0.3.0".
var version = "dev"

var (
	allowV4  = flag.Bool("ipv4", false, "也使用 IPv4 入口（默认只用 IPv6 入口）")
	count    = flag.Int("count", 200, "每次优选测试的入口数量")
	selftest = flag.Bool("selftest", false, "连接、验证后立即退出（用于自动测试）")
	verbose  = flag.Bool("v", false, "显示 WireGuard 调试日志")
	showVer  = flag.Bool("version", false, "显示版本号后退出")
	diag     = flag.Bool("diag", true, "启动时先诊断网络（路由器/运营商/暴雪三段）")
	v6only   = flag.Bool("v6only", true, "出口只走 IPv6，禁用 IPv4；只有 IPv4 的游戏（如守望先锋）要加 -v6only=false")
)

// physIndex is the interface the tunnel's own UDP packets leave through; probes
// are bound to it too, so a rescan while the tunnel is up measures the real path.
var physIndex4, physIndex6 uint32

func main() {
	windows.SetConsoleOutputCP(65001)
	flag.Parse()
	if *showVer {
		fmt.Println("WarpGameBoost " + version)
		return
	}
	setConsoleTitle("WarpGameBoost " + version)
	if !windows.GetCurrentProcessToken().IsElevated() {
		elevate()
		return
	}
	// A second copy would reuse the same adapter (Wintun reuses an adapter by
	// name) and the two would fight over its routes.
	name, _ := windows.UTF16PtrFromString("Local\\WarpGameBoost")
	if h, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		fmt.Println("WarpGameBoost 已经在运行。")
		time.Sleep(3 * time.Second)
		return
	} else if h != 0 {
		defer windows.CloseHandle(h)
	}
	code := run()
	if code != 0 && !*selftest {
		fmt.Println("\n按回车键退出…")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	if code != 0 {
		os.Exit(code)
	}
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
	fmt.Printf("WarpGameBoost %s — Cloudflare WARP 游戏加速（IPv6 入口 IP 优选）\n", version)
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
	if physIndex6 == 0 && !*allowV4 {
		// Without IPv6 the only way in is IPv4; say so and carry on rather than
		// make the user restart with a flag.
		fmt.Println("本机没有 IPv6 网络，改用 IPv4 入口。")
		fmt.Println()
		*allowV4 = true
	}
	if *allowV4 {
		physIndex4 = defaultInterface(winipcfg.AddressFamily(windows.AF_INET), 0)
	}

	var blizzard *series
	if *diag {
		blizzard = diagnose()
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
		fmt.Println("连接失败：", err, "——稍等后重新优选再试一次。")
		time.Sleep(5 * time.Second)
		if results = optimize(acct, ""); len(results) > 0 {
			t, err = start(acct, results)
		}
		if err != nil || t == nil {
			fmt.Println("连接失败：", err)
			return 1
		}
	}
	defer func() {
		t.dev.Close()
		fmt.Println("\n加速已关闭，网络已恢复。")
	}()

	if *verbose {
		fmt.Println(time.Now().Format("15:04:05.000"), "开始验证")
	}
	trace := warpTrace()
	if !strings.Contains(trace, "warp=on") {
		fmt.Println("隧道已建立，但验证失败：", strings.TrimSpace(trace))
		return 1
	}
	if *v6only {
		if _, ok := tcpPing("1.1.1.1:443"); ok {
			fmt.Println("IPv4 仍然可以访问，禁用失败。")
			return 1
		}
		if !strings.Contains(traceField(trace, "ip"), ":") {
			fmt.Println("出口不是 IPv6：", strings.TrimSpace(trace))
			return 1
		}
	}
	fmt.Printf("\n✅ 加速已开启：本机全部网络（包括游戏）经 WARP 入口 %s\n", t.endpoint())
	if *v6only {
		fmt.Printf("   出口仅 IPv6（%s），IPv4 已禁用，DNS 经隧道用 Cloudflare。\n", traceField(trace, "ip"))
		fmt.Println("   只有 IPv4 的网站和游戏会连不上；玩守望先锋请加参数 -v6only=false。")
	} else {
		fmt.Println("   仅流量模式：DNS 保持系统设置。")
		fmt.Println()
		compareWarp(blizzard)
	}
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
	results := scan(acct, *count, *allowV4, physIndex6 != 0, current)
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

	reject *v4Reject // set with -v6only
}

// refreshDNS keeps the IPv4 DNS servers let through -v6only in step with the
// network Windows is on.
func (t *tunnel) refreshDNS() {
	if t.reject != nil {
		t.reject.setAllowed(systemDNS4(t.luid))
	}
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
	level := device.LogLevelSilent
	if *verbose {
		level = device.LogLevelVerbose
	}
	var dev tun.Device = tdev
	if *v6only {
		t.reject = &v4Reject{Device: tdev}
		t.reject.setAllowed(systemDNS4(t.luid))
		if *verbose {
			fmt.Println("经隧道放行的 IPv4 DNS：", systemDNS4(t.luid))
		}
		dev = t.reject
	}
	t.dev = device.NewDevice(dev, t.bind, device.NewLogger(level, "wg: "))
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
	t.rebind()
	// Try the best endpoints until one completes a handshake. An endpoint that
	// answered every probe a moment ago occasionally does not answer the
	// tunnel; moving on beats waiting for its retransmissions.
	ok := false
	for i, r := range results {
		if i == 10 {
			break
		}
		if i > 0 {
			fmt.Printf("入口 %s 没有回应，改试下一个…\n", results[i-1].Endpoint)
			if !t.roam(r.Endpoint) {
				continue
			}
		}
		if t.waitHandshake(6 * time.Second) {
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

// configure gives the adapter WARP's addresses and sends all
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
	// Windows only returns IPv6 addresses for a name when the interface the
	// query went out on has IPv6. On an IPv4-only network that is never the
	// real adapter, so with -v6only the tunnel gets Cloudflare's resolver at
	// its IPv6 addresses, asked through the tunnel.
	if *v6only {
		if err := t.luid.SetDNS(windows.AF_INET6, v6DNS, nil); err != nil {
			return fmt.Errorf("设置 DNS：%w", err)
		}
	}
	// Traffic only: the adapter gets no DNS servers, so Windows keeps resolving
	// with the system's own DNS settings. Queries to a resolver on the local
	// network stay local (its on-link route is more specific than the halves
	// below); queries to a resolver on the internet travel through the tunnel.
	routes := []*winipcfg.RouteData{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: netip.IPv4Unspecified()},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), NextHop: netip.IPv4Unspecified()},
		{Destination: netip.MustParsePrefix("::/1"), NextHop: netip.IPv6Unspecified()},
		{Destination: netip.MustParsePrefix("8000::/1"), NextHop: netip.IPv6Unspecified()},
		// Windows only hands out IPv6 addresses for names when some interface
		// has an IPv6 default route; on an IPv4-only network that has to be
		// this one, or nothing would try the tunnel's IPv6.
		{Destination: netip.MustParsePrefix("::/0"), NextHop: netip.IPv6Unspecified()},
	}
	if err := t.luid.SetRoutes(routes); err != nil {
		return fmt.Errorf("设置路由：%w", err)
	}
	return nil
}

// rebind pins the tunnel's UDP sockets to the current physical interfaces.
func (t *tunnel) rebind() {
	if b, ok := t.bind.(conn.BindSocketToInterface); ok {
		if physIndex6 != 0 {
			b.BindSocketToInterface6(physIndex6, false)
		}
		if physIndex4 != 0 {
			b.BindSocketToInterface4(physIndex4, false)
		}
	}
}

// followNetwork notices when the default route moves to another interface
// (Wi-Fi reconnects, a cable is plugged in, the PC wakes up) and moves the
// tunnel's sockets with it. Without this they stayed bound to the old
// interface and the tunnel was dead until a rescan.
func (t *tunnel) followNetwork() bool {
	i6 := defaultInterface(windows.AF_INET6, t.luid)
	i4 := physIndex4
	if *allowV4 {
		i4 = defaultInterface(windows.AF_INET, t.luid)
	}
	if i6 == physIndex6 && i4 == physIndex4 {
		return false
	}
	physIndex6, physIndex4 = i6, i4
	t.rebind()
	return true
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
			if t.followNetwork() {
				fmt.Printf("\n网络已变化，隧道改走新的网卡。\n")
				t.refreshDNS()
			}
			rtt, ok := tcpPing(pingTarget())
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
	t.followNetwork()
	t.refreshDNS()
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

var v6DNS = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001")}

func pingTarget() string {
	if *v6only {
		return "[2606:4700:4700::1111]:443"
	}
	return "1.1.1.1:443"
}

// systemDNS4 lists the IPv4 DNS servers Windows is using. With -v6only they
// stay reachable through the tunnel, or names would stop resolving on networks
// that hand out a public resolver.
func systemDNS4(skip winipcfg.LUID) []netip.Addr {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, ad := range adapters {
		if ad.OperStatus != winipcfg.IfOperStatusUp || ad.LUID == skip {
			continue
		}
		for d := ad.FirstDNSServerAddress; d != nil; d = d.Next {
			a, ok := netip.AddrFromSlice(d.Address.IP())
			if !ok {
				continue
			}
			a = a.Unmap()
			if a.Is4() && !a.IsLoopback() && !a.IsUnspecified() && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func traceField(trace, key string) string {
	for _, line := range strings.Split(trace, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			return v
		}
	}
	return ""
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
	if *v6only {
		// Go's resolver may hand back only IPv4 addresses here; ask for IPv6.
		d := &net.Dialer{}
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp6", addr)
			},
			ForceAttemptHTTP2: true,
		}
	}
	for i := 0; i < 3; i++ {
		resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return string(b)
		}
		if *verbose {
			fmt.Println(time.Now().Format("15:04:05.000"), "验证请求失败：", err)
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

func setConsoleTitle(title string) {
	p, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleTitleW").Call(uintptr(unsafe.Pointer(p)))
}
