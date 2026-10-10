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

// verdict turns the two measured legs into advice. gw is the router, isp the
// first public hop; either may be nil when it could not be found. hotspot is
// set when the router is a phone sharing its mobile connection.
func verdict(gw, isp *series, wifi, hotspot bool) []string {
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
	case hotspot:
		return []string{
			"你在用手机热点：手机网络本身就比宽带多几十毫秒，延迟也时高时低，WARP 改变不了。",
			"  · 打游戏尽量用家里的宽带（网线最好，其次 Wi-Fi）",
		}
	case bad(isp, true):
		return []string{
			"问题在运营商接入：路由器正常，但出了家门到运营商的第一段就不稳。",
			"  · WARP 加速的流量也要先经过这一段，帮不上；可以打电话让运营商查线路，或换运营商",
		}
	case !measured(gw) && !measured(isp):
		return []string{"路由器和运营商都不回应 ping，没法判断。"}
	default:
		return []string{"家里网络和运营商接入都正常。游戏里仍然卡，就开着加速和不开各打几局，用网络图（Ctrl+Shift+N）对比。"}
	}
}

func report(gw, isp *series, wifi, hotspot bool) string {
	var b strings.Builder
	for _, s := range []*series{gw, isp} {
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
	for _, l := range verdict(gw, isp, wifi, hotspot) {
		b.WriteString(l + "\n")
	}
	return b.String()
}
