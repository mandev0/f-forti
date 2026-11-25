// Package cliauth runs the interactive username/password/2FA login on a
// terminal.
package cliauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"f-forti/internal/forti"
)

// Login prompts for missing credentials and the 2FA code(s) and logs in.
// Returns the username used.
func Login(ctx context.Context, c *forti.Client, in *bufio.Reader, user string) (string, error) {
	if user == "" {
		user = Prompt(in, "Username: ")
	}
	pass, err := ReadSecret(in, "Password: ")
	if err != nil {
		return user, err
	}
	ch, err := c.Login(ctx, user, pass)
	pass = ""
	if err != nil {
		return user, err
	}
	for ch != nil {
		fmt.Printf("\n%s\n", ch.Message)
		hint := "Code: "
		if ch.PushAvailable() {
			hint = "Code (leave empty to send a FortiToken push): "
		}
		code, err := ReadSecret(in, hint)
		if err != nil {
			return user, err
		}
		code = strings.TrimSpace(code)
		push := code == "" && ch.PushAvailable()
		if code == "" && !push {
			return user, errors.New("no code entered")
		}
		if push {
			fmt.Println("Push sent, approve it on your phone…")
		}
		if ch, err = c.Submit2FA(ctx, ch, user, code, push); err != nil {
			return user, err
		}
	}
	return user, nil
}

// Prompt reads one line.
func Prompt(in *bufio.Reader, label string) string {
	fmt.Print(label)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

// ReadSecret reads a line without echo when stdin is a terminal.
func ReadSecret(in *bufio.Reader, label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return Prompt(in, label), nil
	}
	fmt.Print(label)
	b, err := term.ReadPassword(fd)
	fmt.Println()
	return string(b), err
}
