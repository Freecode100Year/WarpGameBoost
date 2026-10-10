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
	ok, gwBad, ispBad := steady("gw", 2, 60), jittery("gw", 60), lossy("isp", 8, 60, 12)
	cases := []struct {
		gw, isp       *series
		wifi, hotspot bool
		want          string
	}{
		{gwBad, ok, true, false, "Wi-Fi"},
		{ok, ispBad, false, false, "运营商接入"},
		{ok, ok, true, true, "手机热点"},
		{ok, ok, false, false, "都正常"},
		{ok, nil, false, false, "都正常"},
		{&series{name: "gw", sent: 60}, nil, false, false, "没法判断"}, // silent router is unmeasured
	}
	for i, c := range cases {
		got := strings.Join(verdict(c.gw, c.isp, c.wifi, c.hotspot), "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("case %d: want %q in\n%s", i, c.want, got)
		}
	}
}
