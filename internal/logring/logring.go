// Package logring is a small logger that keeps the last N lines in memory
// (served to the GUI over IPC) and appends to a size-capped file.
package logring

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Log is safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	lines  []string
	max    int
	f      *os.File
	path   string
	size   int64
	limit  int64
	mirror io.Writer
}

// SetMirror also writes every line to w (e.g. the console in run mode).
func (l *Log) SetMirror(w io.Writer) {
	l.mu.Lock()
	l.mirror = w
	l.mu.Unlock()
}

// New keeps max lines in memory; path may be empty (no file).
func New(max int, path string) *Log {
	l := &Log{max: max, path: path, limit: 5 << 20}
	if path != "" {
		l.open()
	}
	return l
}

func (l *Log) open() {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
	l.f = f
}

// Printf logs one line. Callers must never pass secrets.
func (l *Log) Printf(format string, args ...any) {
	line := time.Now().Format("2006-01-02 15:04:05 ") + fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.max {
		l.lines = l.lines[len(l.lines)-l.max:]
	}
	if l.mirror != nil {
		io.WriteString(l.mirror, line+"\n")
	}
	if l.f != nil {
		n, _ := l.f.WriteString(line + "\n")
		l.size += int64(n)
		if l.size > l.limit {
			l.f.Close()
			_ = os.Rename(l.path, l.path+".1")
			l.size = 0
			l.open()
		}
	}
}

// Lines returns a copy of the buffered lines.
func (l *Log) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// Close closes the file.
func (l *Log) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}
