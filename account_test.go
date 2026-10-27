package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func testAccount() *Account {
	priv := make([]byte, 32)
	priv[0] = 7
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	return &Account{PrivateKey: base64.StdEncoding.EncodeToString(priv), PeerKey: base64.StdEncoding.EncodeToString(pub), AddrV4: "172.16.0.2", AddrV6: "2606:4700:110::2"}
}

func TestLoadAccountRejectsCorruption(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Account)
	}{
		{"private base64", func(a *Account) { a.PrivateKey = "invalid!" }},
		{"short private", func(a *Account) { a.PrivateKey = "AQ==" }},
		{"short peer", func(a *Account) { a.PeerKey = "AQ==" }},
		{"low order peer", func(a *Account) { a.PeerKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"missing IPv4", func(a *Account) { a.AddrV4 = "" }},
		{"wrong IPv6 family", func(a *Account) { a.AddrV6 = "192.0.2.1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := testAccount()
			tc.mutate(a)
			b, _ := json.Marshal(a)
			path := filepath.Join(t.TempDir(), "account.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAccount(path); err == nil {
				t.Fatal("corrupt account accepted")
			}
		})
	}
}

func TestAccountRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "account.json")
	a := testAccount()
	a.Best = "[2606:4700:d0::1]:2408"
	saveAccount(path, a)
	got, err := loadAccount(path)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(a)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Fatal("account changed during save/load")
	}
}
