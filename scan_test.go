package main

import (
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
