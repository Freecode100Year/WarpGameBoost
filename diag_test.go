package main

import (
	"strings"
	"testing"
	"time"
)

func steady(name string, ms int, n int) *series {
	s := &series{name: name, sent: n}
	for i := 0; i < n; i++ {
		s.rtts = append(s.rtts, time.Duration(ms)*time.Millisecond)
	}
	return s
}

func lossy(name string, ms, n, lost int) *series {
	s := steady(name, ms, n-lost)
	s.sent = n
	return s
}

func jittery(name string, n int) *series {
	s := &series{name: name, sent: n}
	for i := 0; i < n; i++ {
		s.rtts = append(s.rtts, time.Duration(2+(i%2)*30)*time.Millisecond)
	}
	return s
}

func TestStats(t *testing.T) {
	st := lossy("x", 10, 20, 2).stats()
	if st.avg != 10*time.Millisecond || st.jitter != 0 || st.loss < 0.099 || st.loss > 0.101 {
		t.Fatalf("%+v", st)
	}
	if j := jittery("x", 10).stats().jitter; j != 30*time.Millisecond {
		t.Fatalf("jitter %v", j)
	}
	s := steady("x", 10, 20)
	s.rtts[5], s.rtts[9] = 200*time.Millisecond, 300*time.Millisecond
	if st := s.stats(); st.spikes != 2 || st.max != 300*time.Millisecond {
		t.Fatalf("%+v", st)
	}
}

func TestVerdict(t *testing.T) {
	ok, gwBad, ispBad, bliz, blizBad := steady("gw", 2, 60), jittery("gw", 60), lossy("isp", 8, 60, 12), steady("b", 70, 30), lossy("b", 70, 30, 3)
	cases := []struct {
		gw, isp, target *series
		wifi            bool
		want            string
	}{
		{gwBad, ok, blizBad, true, "Wi-Fi"},
		{ok, ispBad, blizBad, false, "运营商接入"},
		{ok, ok, blizBad, false, "WARP 加速可能有帮助"},
		{ok, ispBad, bliz, false, "三段都正常"}, // a hop that rate-limits pings alone is not a fault
		{ok, nil, nil, false, "没测到"},
		{&series{name: "gw", sent: 60}, ok, bliz, false, "三段都正常"}, // silent router is unmeasured
	}
	for i, c := range cases {
		got := strings.Join(verdict(c.gw, c.isp, c.target, c.wifi), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("case %d: want %q in\n%s", i, c.want, got)
		}
	}
}

func TestCompareVerdict(t *testing.T) {
	good, bad := steady("", 20, 10).stats(), lossy("", 20, 10, 2).stats()
	if !strings.Contains(compareVerdict(bad, good), "WARP 更稳") ||
		!strings.Contains(compareVerdict(good, bad), "直连更好") ||
		!strings.Contains(compareVerdict(good, good), "差不多") {
		t.Fatal("compare verdict")
	}
}
