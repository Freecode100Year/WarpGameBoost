//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	fmt.Println("WarpGameBoost 只支持 Windows。")
	os.Exit(1)
}

func dialOutside(endpoint string) (net.Conn, error) { return net.Dial("udp", endpoint) }
