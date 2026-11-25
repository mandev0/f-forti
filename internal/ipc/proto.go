// Package ipc defines the GUI/CLI ↔ service protocol: one JSON object per
// line, request/response, strictly validated, size-limited. The transport
// (a locked-down named pipe on Windows) is in pipe_windows.go.
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// MaxMessage bounds one request/response line.
const MaxMessage = 64 << 10

// Ops accepted by the service. Nothing else is.
const (
	OpStatus     = "status"
	OpProfiles   = "profiles"
	OpConnect    = "connect"
	OpSubmit2FA  = "submit2fa"
	OpDisconnect = "disconnect"
	OpLogs       = "logs"
	OpProfileSet = "profile_save"
	OpProfileDel = "profile_delete"
)

// ProfileEdit creates (empty ID) or updates a profile.
type ProfileEdit struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Server      string `json:"server"`
	Realm       string `json:"realm,omitempty"`
	TrustedCert string `json:"trustedCert,omitempty"`
}

// Request from a client.
type Request struct {
	Op       string       `json:"op"`
	Profile  string       `json:"profile,omitempty"`
	Username string       `json:"username,omitempty"`
	Password string       `json:"password,omitempty"`
	Code     string       `json:"code,omitempty"`
	Edit     *ProfileEdit `json:"edit,omitempty"`
}

// Validate rejects malformed requests before they reach the engine.
func (r *Request) Validate() error {
	if r.Edit != nil && r.Op != OpProfileSet {
		return errors.New("edit is only valid with profile_save")
	}
	switch r.Op {
	case OpStatus, OpProfiles, OpDisconnect, OpLogs:
		if r.Profile != "" || r.Username != "" || r.Password != "" || r.Code != "" {
			return errors.New("this operation takes no parameters")
		}
	case OpProfileSet:
		if r.Edit == nil || r.Profile != "" || r.Username != "" || r.Password != "" || r.Code != "" {
			return errors.New("profile_save: only edit is allowed")
		}
	case OpProfileDel:
		if r.Profile == "" || len(r.Profile) > 32 || r.Username != "" || r.Password != "" || r.Code != "" {
			return errors.New("profile_delete: only profile is allowed")
		}
	case OpConnect:
		if r.Profile == "" || r.Username == "" || r.Password == "" || r.Code != "" {
			return errors.New("connect: profile, username and password are required")
		}
		if len(r.Username) > 128 || len(r.Password) > 512 || len(r.Profile) > 32 {
			return errors.New("connect: field too long")
		}
	case OpSubmit2FA:
		if r.Code == "" || len(r.Code) > 64 || r.Profile != "" || r.Username != "" || r.Password != "" {
			return errors.New("submit2fa: only code is allowed")
		}
	default:
		return fmt.Errorf("unknown operation %q", r.Op)
	}
	return nil
}

// State of the service connection.
type State string

const (
	StateIdle          State = "idle"
	StateNeed2FA       State = "need_2fa"
	StateConnecting    State = "connecting"
	StateConnected     State = "connected"
	StateDisconnecting State = "disconnecting"
	StateError         State = "error"
)

// Status is the service state snapshot.
type Status struct {
	State     State     `json:"state"`
	Profile   string    `json:"profile,omitempty"`
	Username  string    `json:"username,omitempty"`
	Message   string    `json:"message,omitempty"` // 2FA prompt or progress text
	LocalIP   string    `json:"localIp,omitempty"`
	Since     time.Time `json:"since,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"` // gateway auth-timeout
	Routes    int       `json:"routes,omitempty"`
	DNSRules  []string  `json:"dnsRules,omitempty"` // human readable
	Warnings  []string  `json:"warnings,omitempty"`
	LastError string    `json:"lastError,omitempty"`
	RxBytes   uint64    `json:"rxBytes,omitempty"`
	TxBytes   uint64    `json:"txBytes,omitempty"`
}

// ProfileInfo is what clients may know about a profile.
type ProfileInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Server      string `json:"server"`
	Realm       string `json:"realm,omitempty"`
	TrustedCert string `json:"trustedCert,omitempty"`
}

// Response from the service.
type Response struct {
	OK       bool          `json:"ok"`
	Error    string        `json:"error,omitempty"`
	Status   *Status       `json:"status,omitempty"`
	Profiles []ProfileInfo `json:"profiles,omitempty"`
	Locked   bool          `json:"locked,omitempty"` // profiles are admin-managed
	ID       string        `json:"id,omitempty"`     // profile_save result
	Logs     []string      `json:"logs,omitempty"`
}

// Handler serves one request.
type Handler func(Request) Response

// ServeConn handles requests on c until EOF/idle timeout.
func ServeConn(c net.Conn, h Handler) error {
	defer c.Close()
	r := bufio.NewReaderSize(c, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		line, err := readLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var req Request
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var resp Response
		if err := dec.Decode(&req); err != nil {
			resp = Response{Error: "invalid request"}
		} else if err := req.Validate(); err != nil {
			resp = Response{Error: err.Error()}
		} else {
			resp = h(req)
		}
		req.Password, req.Code = "", ""
		if err := writeMsg(c, resp); err != nil {
			return err
		}
	}
}

// Client is a synchronous request/response client.
type Client struct {
	c net.Conn
	r *bufio.Reader
}

// NewClient wraps an established connection.
func NewClient(c net.Conn) *Client { return &Client{c: c, r: bufio.NewReaderSize(c, 4096)} }

// Do sends req and waits for the response.
func (cl *Client) Do(req Request, timeout time.Duration) (*Response, error) {
	_ = cl.c.SetDeadline(time.Now().Add(timeout))
	if err := writeMsg(cl.c, req); err != nil {
		return nil, err
	}
	line, err := readLine(cl.r)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Close closes the connection.
func (cl *Client) Close() error { return cl.c.Close() }

func writeMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) >= MaxMessage {
		return errors.New("message too large")
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		buf = append(buf, chunk...)
		if len(buf) >= MaxMessage {
			return nil, errors.New("message too large")
		}
		if !isPrefix {
			return buf, nil
		}
	}
}
