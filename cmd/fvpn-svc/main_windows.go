//go:build windows

// fvpn-svc is the privileged half of FVPN: a LocalSystem Windows service that
// owns the tunnel, the Wintun adapter, routes and NRPT rules, and is
// controlled over a locked-down named pipe.
//
// Installed and removed with the MSI (FVPN-x.y.z.msi), which calls
// "fvpn-svc msi-configure" once as SYSTEM.
//
//	fvpn-svc profile-add -id main -name "Work" -server host:port -trusted-cert SHA256
//	fvpn-svc profile-remove -id main
//	fvpn-svc allow-user DOMAIN\user | deny-user DOMAIN\user
//	fvpn-svc show
//	fvpn-svc run                            (foreground, elevated, for testing)
//	fvpn-svc service                        (started by SCM)
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"f-forti/internal/config"
	"f-forti/internal/engine"
	"f-forti/internal/ipc"
	"f-forti/internal/logring"
	"f-forti/internal/winnet"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: fvpn-svc <command>
  profile-add -id ID -name NAME -server HOST:PORT [-realm R] [-trusted-cert SHA256] [-allowed-networks CIDR,...]
  profile-remove -id ID
  allow-user USER | deny-user USER
  lock-profiles on|off         disable/enable profile editing in the app
  show                         show the configuration
  run                          run in the foreground (testing, admin)`)
	os.Exit(2)
}

func main() {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		runService()
		return
	}
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "install", "uninstall":
		err = fmt.Errorf("FVPN is installed with FVPN-<version>.msi and removed from Settings › Apps")
	case "msi-configure":
		err = cmdMSIConfigure(args)
	case "profile-add":
		err = cmdProfileAdd(args)
	case "profile-remove":
		err = cmdProfileRemove(args)
	case "allow-user":
		err = cmdUser(args, true)
	case "deny-user":
		err = cmdUser(args, false)
	case "show":
		err = cmdShow()
	case "lock-profiles":
		err = cmdLock(args)
	case "run":
		err = cmdRun()
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// serve runs the engine and the control pipe until ctx is done.
func serve(ctx context.Context, asService bool, log *logring.Log) error {
	dataDir, err := dataDir()
	if err != nil {
		return err
	}
	if err := checkDataDir(dataDir); err != nil {
		return err
	}
	cfgPath := configPath(dataDir)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	nw := winnet.New(dataDir, log.Printf)
	nw.CleanupStale()

	eng := engine.New(engine.Options{
		Network: nw,
		Config:  func() (*config.Config, error) { return config.Load(cfgPath) },
		Save:    func(c *config.Config) error { return config.Save(cfgPath, c) },
		Logf:    log.Printf,
		Echo:    30 * time.Second,
	})
	handler := func(r ipc.Request) ipc.Response {
		if r.Op == ipc.OpLogs {
			return ipc.Response{OK: true, Logs: log.Lines()}
		}
		return eng.Handle(r)
	}

	ln, err := ipc.Listen(cfg.AllowedUsers, asService)
	if err != nil {
		return fmt.Errorf("cannot open the control pipe: %w", err)
	}
	log.Printf("service started (allowed users: %d, profiles: %d)", len(cfg.AllowedUsers), len(cfg.Profiles))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // concurrent clients
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			sid, elevated, err := ipc.ClientIdentity(c)
			if err != nil || !ipc.Allowed(sid, elevated, cfg.AllowedUsers) {
				log.Printf("rejected pipe client: sid=%s elevated=%v err=%v", sid, elevated, err)
				c.Close()
				continue
			}
			select {
			case sem <- struct{}{}:
			default:
				c.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				ipc.ServeConn(c, func(r ipc.Request) ipc.Response {
					if r.Op != ipc.OpStatus && r.Op != ipc.OpLogs {
						log.Printf("request: %s (sid %s)", r.Op, sid)
					}
					return handler(r)
				})
			}()
		}
	}()

	<-ctx.Done()
	ln.Close()
	eng.Disconnect()
	nw.Down()
	log.Printf("service stopped")
	return nil
}

type service struct{}

func (service) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	dir, _ := dataDir()
	log := logring.New(500, logPath(dir))
	defer log.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, true, log) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-errc:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			}
		case err := <-errc:
			cancel()
			if err != nil {
				log.Printf("service error: %v", err)
				return true, 1
			}
			return false, 0
		}
	}
}

func runService() {
	if err := svc.Run(ipc.ServiceName, service{}); err != nil {
		os.Exit(1)
	}
}

func cmdRun() error {
	if err := requireElevated(); err != nil {
		return err
	}
	if pid, err := ipc.ServicePID(); err == nil {
		return fmt.Errorf("the service is already running (pid %d); stop it first: sc stop %s", pid, ipc.ServiceName)
	}
	log := logring.New(500, "")
	log.SetMirror(os.Stdout)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	fmt.Println("running in the foreground; connect with fvpn-ctl -dev. Ctrl+C to exit.")
	return serve(ctx, false, log)
}

func requireElevated() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("this command must be run as administrator")
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
