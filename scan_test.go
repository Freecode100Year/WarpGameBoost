package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"sync"
	"testing"
)

// Concurrent probes must never share a handshake timestamp slot, or the
// server drops one of them as a replay.
func TestProbeStampsAreStrictlyIncreasing(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := string(tai64n(probeStamp()))
			mu.Lock()
			defer mu.Unlock()
			if seen[k] {
				t.Errorf("two probes share a timestamp")
			}
			seen[k] = true
		}()
	}
	wg.Wait()
}

// Invalid scanner inputs must not panic or send malformed handshakes.
func TestScanRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		a      *Account
		count  int
		v4, v6 bool
	}{
		{"no families", testAccount(), 1, false, false},
		{"nil account", nil, 1, true, false},
		{"bad keys", &Account{PrivateKey: "AQ==", PeerKey: "AQ=="}, 1, true, false},
		{"zero count", testAccount(), 0, true, false},
		{"negative count", testAccount(), -1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("scan panicked: %v", r)
				}
			}()
			if got := scan(tc.a, tc.count, tc.v4, tc.v6, ""); len(got) != 0 {
				t.Errorf("invalid scan returned %d endpoints", len(got))
			}
		})
	}
}

// An old reply must not be counted as the answer to a newer initiation.
func TestProbeRejectsWrongReceiver(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != 148 {
				continue
			}
			reply := make([]byte, 92)
			reply[0] = 2
			copy(reply[8:12], buf[4:8])
			reply[8] ^= 0xff
			conn.WriteTo(reply, addr)
		}
	}()
	defer func() { conn.Close(); <-done }()
	a := testAccount()
	priv, _ := base64.StdEncoding.DecodeString(a.PrivateKey)
	peer, _ := base64.StdEncoding.DecodeString(a.PeerKey)
	if r, ok := probeEndpoint(conn.LocalAddr().String(), priv, peer); ok {
		t.Errorf("unrelated handshake replies counted as reachable: %+v", r)
	}
}

func TestProbeIgnoresStaleReplyBeforeCurrentReply(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != 148 {
				continue
			}
			reply := make([]byte, 92)
			reply[0] = 2
			copy(reply[8:12], buf[4:8])
			stale := bytes.Clone(reply)
			stale[8] ^= 0xff
			conn.WriteTo(stale, addr)
			conn.WriteTo(reply, addr)
		}
	}()
	defer func() { conn.Close(); <-done }()
	a := testAccount()
	priv, _ := base64.StdEncoding.DecodeString(a.PrivateKey)
	peer, _ := base64.StdEncoding.DecodeString(a.PeerKey)
	if r, ok := probeEndpoint(conn.LocalAddr().String(), priv, peer); !ok || r.Loss != 0 {
		t.Errorf("current replies lost behind stale packets: %+v, reachable %v", r, ok)
	}
}
