package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// series holds one diagnostic target's samples: a reply time per answered
// probe, and how many probes were sent.
type series struct {
	name string
	rtts []time.Duration
	sent int
}

type stats struct {
	avg, jitter, max time.Duration
	loss             float64 // 0..1
	spikes           int     // replies more than 50 ms above the median
}

func (s *series) stats() stats {
	var st stats
	if s.sent == 0 {
		return st
	}
	st.loss = 1 - float64(len(s.rtts))/float64(s.sent)
	if len(s.rtts) == 0 {
		return st
	}
	var sum, dsum time.Duration
	for i, r := range s.rtts {
		sum += r
		st.max = max(st.max, r)
		if i > 0 {
			d := r - s.rtts[i-1]
			if d < 0 {
				d = -d
			}
			dsum += d
		}
	}
	st.avg = sum / time.Duration(len(s.rtts))
	if len(s.rtts) > 1 {
		st.jitter = dsum / time.Duration(len(s.rtts)-1)
	}
	sorted := append([]time.Duration(nil), s.rtts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	median := sorted[len(sorted)/2]
	for _, r := range s.rtts {
		if r > median+50*time.Millisecond {
			st.spikes++
		}
	}
	return st
}

// unstable reports whether a hop shows the kind of trouble a game feels: lost
// packets, jitter, or repeated spikes. Routers answer pings at low priority,
// so the intermediate ISP hop gets a looser bar than the endpoints.
func (st stats) unstable(lenient bool) bool {
	lossBar, jitterBar := 0.03, 8*time.Millisecond
	if lenient {
		lossBar, jitterBar = 0.10, 15*time.Millisecond
	}
	return st.loss >= lossBar || st.jitter > jitterBar || st.spikes >= 2
}

func (st stats) String() string {
	return fmt.Sprintf("延迟 %3d ms  抖动 %2d ms  最高 %3d ms  丢包 %2.0f%%",
		st.avg.Milliseconds(), st.jitter.Milliseconds(), st.max.Milliseconds(), st.loss*100)
}

// verdict turns the three hops into advice. gw is the router, isp the first
// public hop, target a Blizzard server; any may be nil when it could not be
// found or measured.
func verdict(gw, isp, target *series, wifi bool) []string {
	// A hop that never answered is unmeasured, not broken: plenty of
	// routers ignore pings altogether.
	measured := func(s *series) bool { return s != nil && len(s.rtts) > 0 }
	bad := func(s *series, lenient bool) bool { return measured(s) && s.stats().unstable(lenient) }
	link := "网线/路由器"
	if wifi {
		link = "Wi-Fi"
	}
	switch {
	case bad(gw, false):
		lines := []string{"问题在家里：电脑到路由器这一段就不稳（" + link + "）。WARP 加速帮不上，先解决这一段："}
		if wifi {
			lines = append(lines,
				"  · 能插网线就插网线，效果最明显；不能的话连 5GHz、靠近路由器",
				"  · Windows 设置 → 隐私和安全性 → 定位，关闭（定位会让网卡定期扫描 Wi-Fi，造成延迟尖峰）",
				"  · 设备管理器 → 无线网卡 → 电源管理，取消“允许计算机关闭此设备以节约电源”")
		} else {
			lines = append(lines, "  · 换一根网线或换个路由器口试试；重启路由器")
		}
		return append(lines, "  · 家里有人在下载、看视频、传文件时最明显：路由器有 SQM/QoS 就打开")
	case bad(target, false) && bad(isp, true):
		return []string{
			"问题在运营商接入：路由器正常，但出了家门到运营商的第一段就不稳。",
			"  · WARP 加速的流量也要先经过这一段，帮不上；可以打电话让运营商查线路，或换运营商",
		}
	case bad(target, false):
		return []string{
			"问题在运营商到暴雪的线路：家里和运营商接入都正常，往后才不稳。",
			"  · 这种情况 WARP 加速可能有帮助：守望先锋只有 IPv4，请用 -v6only=false 运行，开和不开各打几局对比",
		}
	case !measured(target):
		return []string{"家里网络和运营商接入正常；暴雪服务器没测到，无法判断后面的线路。"}
	default:
		return []string{
			"三段都正常，网络本身没有明显问题。",
			"  · 游戏里仍然卡，可能是游戏服务器或本机（后台下载、同步、杀毒扫描）",
			"  · 不一定需要加速；想试试 WARP，守望先锋请用 -v6only=false",
		}
	}
}

// compareVerdict weighs the direct route against WARP the way a game would:
// loss and jitter first, then latency.
func compareVerdict(direct, warp stats) string {
	score := func(st stats) time.Duration {
		return st.avg + 2*st.jitter + time.Duration(st.loss*1000)*time.Millisecond
	}
	d, w := score(direct), score(warp)
	switch {
	case w+5*time.Millisecond < d:
		return "WARP 更稳，建议开着加速打游戏。"
	case d+5*time.Millisecond < w:
		return "直连更好：WARP 绕远了。建议关掉加速直接玩。"
	default:
		return "两者差不多，开不开都行；以游戏里的网络图（Ctrl+Shift+N）为准。"
	}
}

func report(hops []*series, gw, isp, target *series, wifi bool) string {
	var b strings.Builder
	for _, s := range hops {
		if s == nil {
			continue
		}
		if s.sent == 0 || len(s.rtts) == 0 {
			fmt.Fprintf(&b, "   %-26s 没有回应\n", s.name)
			continue
		}
		fmt.Fprintf(&b, "   %-26s %s\n", s.name, s.stats())
	}
	b.WriteString("\n")
	for _, l := range verdict(gw, isp, target, wifi) {
		b.WriteString(l + "\n")
	}
	return b.String()
}
