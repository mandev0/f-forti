package ipc

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeConn(t *testing.T) {
	a, b := net.Pipe()
	var got []Request
	go ServeConn(b, func(r Request) Response {
		got = append(got, r)
		return Response{OK: true, Status: &Status{State: StateIdle}}
	})
	cl := NewClient(a)
	defer cl.Close()

	resp, err := cl.Do(Request{Op: OpStatus}, time.Second)
	if err != nil || !resp.OK || resp.Status.State != StateIdle {
		t.Fatal(resp, err)
	}
	// invalid op never reaches the handler
	resp, err = cl.Do(Request{Op: "exec"}, time.Second)
	if err != nil || resp.OK || !strings.Contains(resp.Error, "unknown") {
		t.Fatal(resp, err)
	}
	// parameters on a parameterless op are refused
	resp, _ = cl.Do(Request{Op: OpStatus, Profile: "x"}, time.Second)
	if resp.OK {
		t.Fatal("parametreli status kabul edildi")
	}
	// unknown JSON fields are refused
	a.Write([]byte(`{"op":"status","path":"C:\\x"}` + "\n"))
	line, _ := readLine(cl.r)
	if !strings.Contains(string(line), "invalid") {
		t.Fatalf("bilinmeyen alan kabul edildi: %s", line)
	}
	if len(got) != 1 {
		t.Fatalf("handler %d kez çağrıldı", len(got))
	}
}

func TestOversizeRejected(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- ServeConn(b, func(Request) Response { return Response{OK: true} }) }()
	go a.Write([]byte(strings.Repeat("x", MaxMessage+10)))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("büyük mesaj hata vermeliydi")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("zaman aşımı")
	}
	a.Close()
}
