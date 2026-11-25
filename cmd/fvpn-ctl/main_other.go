//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "fvpn-ctl only runs on Windows")
	os.Exit(1)
}
