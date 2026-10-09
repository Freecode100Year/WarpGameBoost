package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Account is the registered WARP device.
type Account struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	PrivateKey string `json:"private_key"` // base64
	PeerKey    string `json:"peer_public_key"`
	AddrV4     string `json:"address_v4"`
	AddrV6     string `json:"address_v6"`
	EndpointV4 string `json:"endpoint_v4"` // host only
	EndpointV6 string `json:"endpoint_v6"`
	Ports      []int  `json:"ports"`
	// Result of the last endpoint optimisation.
	Best      string    `json:"best_endpoint,omitempty"`
	BestRTTms int       `json:"best_rtt_ms,omitempty"`
	ScannedAt time.Time `json:"scanned_at,omitempty"`
}

func loadAccount(path string) (*Account, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Account
	if err := json.Unmarshal(b, &a); err != nil || a.PrivateKey == "" || a.PeerKey == "" {
		return nil, fmt.Errorf("invalid account file")
	}
	return &a, nil
}

func saveAccount(path string, a *Account) {
	b, _ := json.MarshalIndent(a, "", "  ")
	os.MkdirAll(filepath.Dir(path), 0o700)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, path)
	}
}

// register creates a free WARP device, the same way the WARP apps do.
func register() (*Account, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"key": base64.StdEncoding.EncodeToString(pub), "type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": true,
	})
	req, _ := http.NewRequest("POST", "https://api.cloudflareclient.com/v0a2158/reg", bytes.NewReader(body))
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.11-2158")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var r struct {
		ID     string `json:"id"`
		Token  string `json:"token"`
		Config struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4    string `json:"v4"`
					V6    string `json:"v6"`
					Ports []int  `json:"ports"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Config.Peers) == 0 {
		return nil, fmt.Errorf("unexpected registration reply")
	}
	p := r.Config.Peers[0]
	hostOnly := func(s string) string {
		if h, _, err := net.SplitHostPort(s); err == nil {
			return h
		}
		return strings.Trim(s, "[]")
	}
	return &Account{
		ID: r.ID, Token: r.Token, PrivateKey: base64.StdEncoding.EncodeToString(priv[:]), PeerKey: p.PublicKey,
		AddrV4: r.Config.Interface.Addresses.V4, AddrV6: r.Config.Interface.Addresses.V6,
		EndpointV4: hostOnly(p.Endpoint.V4), EndpointV6: hostOnly(p.Endpoint.V6), Ports: p.Endpoint.Ports,
	}, nil
}
