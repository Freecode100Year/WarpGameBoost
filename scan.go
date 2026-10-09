package main

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Endpoint optimisation ("IP 优选"): Cloudflare answers WARP on many addresses and
// UDP ports, and the best one differs by network. WireGuard handshake initiations
// are sent to a sample of them; latency, jitter and loss of the handshake replies
// are the score. The tunnel then roams to the winner without dropping connections.

var (
	warpPrefixesV4 = []string{"162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"}
	warpPrefixesV6 = []string{"2606:4700:d0::/48", "2606:4700:d1::/48"}
	warpPorts      = []int{2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}
)

type scored struct {
	Endpoint string
	RTT      time.Duration // average of the answered handshakes
	Jitter   time.Duration // max - min of the answered handshakes
	Loss     int           // percent of handshakes unanswered
}

// Score ranks endpoints for games: a steady connection matters more than the
// lowest single reply, so jitter counts double and every lost handshake costs
// as much as 20 ms.
func (s scored) Score() time.Duration {
	return s.RTT + 2*s.Jitter + time.Duration(s.Loss)*time.Millisecond
}

const probesPerEndpoint = 5

// scan probes about `count` random endpoints of the allowed families and
// returns the reachable ones, best first.
func scan(a *Account, count int, v4, v6 bool, current string) []scored {
	priv, _ := base64.StdEncoding.DecodeString(a.PrivateKey)
	peer, _ := base64.StdEncoding.DecodeString(a.PeerKey)
	var cands []string
	seen := map[string]bool{}
	add := func(ep string) {
		ap, err := netip.ParseAddrPort(ep)
		if err != nil || seen[ep] || (ap.Addr().Is4() && !v4) || (ap.Addr().Is6() && !v6) {
			return
		}
		seen[ep] = true
		cands = append(cands, ep)
	}
	for _, ep := range []string{current, a.Best} {
		add(ep)
	}
	for _, p := range []int{2408, 500, 1701, 4500} {
		if a.EndpointV4 != "" {
			add(net.JoinHostPort(a.EndpointV4, strconv.Itoa(p)))
		}
		if a.EndpointV6 != "" {
			add(net.JoinHostPort(a.EndpointV6, strconv.Itoa(p)))
		}
	}
	var prefixes []string
	if v4 {
		prefixes = append(prefixes, warpPrefixesV4...)
	}
	if v6 {
		prefixes = append(prefixes, warpPrefixesV6...)
	}
	for tries := 0; len(cands) < count && tries < count*4; tries++ {
		ip := randomAddr(netip.MustParsePrefix(prefixes[randInt(len(prefixes))]))
		add(net.JoinHostPort(ip.String(), strconv.Itoa(warpPorts[randInt(len(warpPorts))])))
	}

	results := make([]scored, 0, len(cands))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 48) // gentle on the network and on Cloudflare
	for _, ep := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(ep string) {
			defer wg.Done()
			defer func() { <-sem }()
			if r, ok := probeEndpoint(ep, priv, peer); ok {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(ep)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Score() < results[j].Score() })
	return results
}

// probeEndpoint sends a few handshake initiations and measures the replies. At
// least two answers are needed; a single lucky reply does not win.
func probeEndpoint(endpoint string, priv, peer []byte) (scored, bool) {
	conn, err := dialOutside(endpoint)
	if err != nil {
		return scored{}, false
	}
	defer conn.Close()
	var sum, lo, hi time.Duration
	replies := 0
	buf := make([]byte, 256)
	for i := 0; i < probesPerEndpoint; i++ {
		msg := handshakeInitiation(priv, peer)
		start := time.Now()
		if _, err := conn.Write(msg); err != nil {
			return scored{}, false
		}
		conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n != 92 || buf[0] != 2 {
			continue
		}
		rtt := time.Since(start)
		replies++
		sum += rtt
		if lo == 0 || rtt < lo {
			lo = rtt
		}
		if rtt > hi {
			hi = rtt
		}
	}
	if replies < 2 {
		return scored{}, false
	}
	return scored{Endpoint: endpoint, RTT: sum / time.Duration(replies), Jitter: hi - lo,
		Loss: (probesPerEndpoint - replies) * 100 / probesPerEndpoint}, true
}

// handshakeInitiation builds a WireGuard (Noise_IKpsk2) handshake initiation.
func handshakeInitiation(staticPriv, peerPub []byte) []byte {
	const construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	const identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	c := blake2s.Sum256([]byte(construction))
	h := hashAll(c[:], []byte(identifier))
	h = hashAll(h[:], peerPub)

	var ePriv [32]byte
	rand.Read(ePriv[:])
	ePriv[0] &= 248
	ePriv[31] = (ePriv[31] & 127) | 64
	ePub, _ := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	staticPub, _ := curve25519.X25519(staticPriv, curve25519.Basepoint)

	msg := make([]byte, 148)
	msg[0] = 1
	var idx [4]byte
	rand.Read(idx[:])
	copy(msg[4:8], idx[:])
	copy(msg[8:40], ePub)

	ck := kdf1(c[:], ePub)
	h = hashAll(h[:], ePub)
	dh1, _ := curve25519.X25519(ePriv[:], peerPub)
	ck, k := kdf2(ck, dh1)
	encStatic := seal(k, staticPub, h[:])
	copy(msg[40:88], encStatic)
	h = hashAll(h[:], encStatic)
	dh2, _ := curve25519.X25519(staticPriv, peerPub)
	_, k = kdf2(ck, dh2)
	encTime := seal(k, tai64n(probeStamp()), h[:])
	copy(msg[88:116], encTime)

	macKey := hashAll([]byte("mac1----"), peerPub)
	mac, _ := blake2s.New128(macKey[:])
	mac.Write(msg[:116])
	copy(msg[116:132], mac.Sum(nil))
	return msg
}

func hashAll(parts ...[]byte) [32]byte {
	d, _ := blake2s.New256(nil)
	for _, p := range parts {
		d.Write(p)
	}
	var out [32]byte
	copy(out[:], d.Sum(nil))
	return out
}

func newBlake() hash.Hash { d, _ := blake2s.New256(nil); return d }

func hmacSum(key, data []byte) []byte {
	m := hmac.New(newBlake, key)
	m.Write(data)
	return m.Sum(nil)
}

func kdf1(key, input []byte) []byte {
	prk := hmacSum(key, input)
	return hmacSum(prk, []byte{1})
}

func kdf2(key, input []byte) ([]byte, []byte) {
	prk := hmacSum(key, input)
	t1 := hmacSum(prk, []byte{1})
	t2 := hmacSum(prk, append(append([]byte{}, t1...), 2))
	return t1, t2
}

func seal(key, plain, ad []byte) []byte {
	aead, _ := chacha20poly1305.New(key)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plain, ad)
}

// probeStamp returns the current time once its handshake timestamp is strictly
// newer than every probe sent before it. All probes carry the same static key,
// and a WARP server drops an initiation whose timestamp is not newer than the
// last one it saw from that key. Endpoints are anycast, so concurrent probes to
// different addresses often reach the same server; when two shared a ~16 ms
// timestamp slot one was dropped, and the endpoint was charged a lost reply it
// never lost (about one in five in practice). Waiting for the next slot caps
// probing at ~60 handshakes a second, and using real time rather than a
// counter keeps the tunnel's own next handshake newer than all of them.
func probeStamp() time.Time {
	stampMu.Lock()
	defer stampMu.Unlock()
	for {
		t := time.Now()
		slot := t.Unix()<<32 | int64(uint32(t.Nanosecond())&^whitenerMask)
		if slot > lastSlot {
			lastSlot = slot
			return t
		}
		time.Sleep(2 * time.Millisecond)
	}
}

var (
	stampMu  sync.Mutex
	lastSlot int64
)

const whitenerMask = uint32(0x1000000 - 1)

// tai64n encodes the handshake timestamp the way wireguard-go does: nanoseconds
// rounded down to about 16 ms. The server only accepts an initiation whose timestamp
// is newer than the last one it saw from this key, so the probes must never carry a
// finer (and therefore possibly newer) timestamp than the tunnel's own next handshake.
func tai64n(t time.Time) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out[:8], uint64(0x400000000000000a)+uint64(t.Unix()))
	binary.BigEndian.PutUint32(out[8:], uint32(t.Nanosecond())&^whitenerMask)
	return out
}

func randInt(n int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

func randomAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := bits / 8; i < len(b); i++ {
		r := byte(randInt(256))
		if i == bits/8 && bits%8 != 0 {
			mask := byte(0xff >> (bits % 8))
			b[i] = b[i]&^mask | r&mask
		} else {
			b[i] = r
		}
	}
	// Avoid .0 and .255 in IPv4.
	if len(b) == 4 && (b[3] == 0 || b[3] == 255) {
		b[3] = byte(1 + randInt(254))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
