package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// disconnectVPNs disconnects the VPNs this program knows how to: the official
// WARP client, Windows' built-in VPN connections, and WireGuard tunnels. They
// stay disconnected after this program exits; reconnect them by hand. It
// returns what it disconnected.
func disconnectVPNs() []string {
	var done []string
	if warpCLIConnected() {
		runQuiet(warpCLI(), "--accept-tos", "disconnect")
		done = append(done, "Cloudflare WARP 官方客户端")
	}
	for _, name := range windowsVPNs() {
		runQuiet("rasdial", name, "/disconnect")
		done = append(done, name+"（Windows VPN）")
	}
	done = append(done, stopWireGuardTunnels()...)
	// Give adapters a moment to drop their routes.
	for i := 0; len(done) > 0 && i < 20 && otherVPN() != ""; i++ {
		time.Sleep(500 * time.Millisecond)
	}
	return done
}

func warpCLI() string {
	return filepath.Join(os.Getenv("ProgramFiles"), "Cloudflare", "Cloudflare WARP", "warp-cli.exe")
}

func warpCLIConnected() bool {
	if _, err := os.Stat(warpCLI()); err != nil {
		return false
	}
	out := runQuiet(warpCLI(), "--accept-tos", "status")
	return strings.Contains(out, "Connected") && !strings.Contains(out, "Disconnected")
}

// windowsVPNs lists the connected VPN profiles of Windows' own VPN client.
func windowsVPNs() []string {
	out := runQuiet("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"@(Get-VpnConnection; Get-VpnConnection -AllUserConnection) | Where-Object ConnectionStatus -eq 'Connected' | ForEach-Object Name")
	var names []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names
}

// stopWireGuardTunnels stops running WireGuard for Windows tunnels; each one
// is a service named WireGuardTunnel$<name>.
func stopWireGuardTunnels() []string {
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	names, _ := m.ListServices()
	var done []string
	for _, n := range names {
		tunnel, ok := strings.CutPrefix(n, "WireGuardTunnel$")
		if !ok {
			continue
		}
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			if _, err := s.Control(svc.Stop); err == nil {
				done = append(done, tunnel+"（WireGuard）")
			}
		}
		s.Close()
	}
	return done
}

// runQuiet executes a command without a console window and returns its output.
func runQuiet(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, _ := cmd.CombinedOutput()
	return string(out)
}
