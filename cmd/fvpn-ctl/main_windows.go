//go:build windows

// fvpn-ctl controls the FVPN service from the command line (no admin rights
// needed for allowed users).
//
//	fvpn-ctl status | profiles | logs | disconnect
//	fvpn-ctl connect -profile main [-user ad]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"f-forti/internal/cliauth"
	"f-forti/internal/ipc"
)

var dev = flag.Bool("dev", false, `connect to a foreground "fvpn-svc run" server (accepts an elevated server)`)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: fvpn-ctl [-dev] status|profiles|logs|disconnect|connect -profile ID [-user NAME]")
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	cl, err := ipc.Dial(3*time.Second, ipc.DialOptions{AllowElevatedServer: *dev})
	check(err)
	defer cl.Close()

	switch flag.Arg(0) {
	case "status":
		printStatus(do(cl, ipc.Request{Op: ipc.OpStatus}).Status)
	case "profiles":
		for _, p := range do(cl, ipc.Request{Op: ipc.OpProfiles}).Profiles {
			fmt.Printf("%-12s %-24s %s\n", p.ID, p.Name, p.Server)
		}
	case "logs":
		for _, l := range do(cl, ipc.Request{Op: ipc.OpLogs}).Logs {
			fmt.Println(l)
		}
	case "disconnect":
		printStatus(do(cl, ipc.Request{Op: ipc.OpDisconnect}).Status)
	case "connect":
		connect(cl, flag.Args()[1:])
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func connect(cl *ipc.Client, args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	profile := fs.String("profile", "", "profile id")
	user := fs.String("user", "", "username")
	fs.Parse(args)
	if *profile == "" {
		check(fmt.Errorf("-profile is required (see: fvpn-ctl profiles)"))
	}
	in := bufio.NewReader(os.Stdin)
	if *user == "" {
		*user = cliauth.Prompt(in, "Username: ")
	}
	pass, err := cliauth.ReadSecret(in, "Password: ")
	check(err)
	resp := do(cl, ipc.Request{Op: ipc.OpConnect, Profile: *profile, Username: *user, Password: pass})
	pass = ""
	for resp.Status != nil && resp.Status.State == ipc.StateNeed2FA {
		fmt.Println(resp.Status.Message)
		code, err := cliauth.ReadSecret(in, "Code: ")
		check(err)
		resp = do(cl, ipc.Request{Op: ipc.OpSubmit2FA, Code: strings.TrimSpace(code)})
	}
	last := ""
	for {
		s := do(cl, ipc.Request{Op: ipc.OpStatus}).Status
		if s.Message != "" && s.Message != last {
			fmt.Println("…", s.Message)
			last = s.Message
		}
		switch s.State {
		case ipc.StateConnected, ipc.StateError, ipc.StateIdle:
			printStatus(s)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func do(cl *ipc.Client, r ipc.Request) *ipc.Response {
	resp, err := cl.Do(r, 2*time.Minute)
	check(err)
	if !resp.OK {
		if resp.Status != nil {
			printStatus(resp.Status)
		}
		check(fmt.Errorf("%s", resp.Error))
	}
	return resp
}

func printStatus(s *ipc.Status) {
	if s == nil {
		return
	}
	fmt.Printf("state   : %s\n", s.State)
	if s.Profile != "" {
		fmt.Printf("profile : %s (%s)\n", s.Profile, s.Username)
	}
	if s.LocalIP != "" {
		fmt.Printf("IP      : %s\n", s.LocalIP)
		fmt.Printf("uptime  : %s (session ends %s)\n", time.Since(s.Since).Round(time.Second), s.ExpiresAt.Local().Format("15:04"))
		fmt.Printf("routes  : %d\n", s.Routes)
		for _, d := range s.DNSRules {
			fmt.Printf("DNS     : %s\n", d)
		}
		fmt.Printf("traffic : rx %d B, tx %d B\n", s.RxBytes, s.TxBytes)
	}
	for _, w := range s.Warnings {
		fmt.Printf("warning : %s\n", w)
	}
	if s.LastError != "" {
		fmt.Printf("error   : %s\n", s.LastError)
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
