package forti

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// debugRT logs requests/responses with secrets removed. Request bodies are
// never logged (they contain the password / OTP).
type debugRT struct {
	next http.RoundTripper
	w    io.Writer
}

var reSecretFields = regexp.MustCompile(`(?i)(SVPNCOOKIE|credential|code2?|magic|reqid)=([^,;&\s"]*)`)

func redactSecrets(s string) string {
	return reSecretFields.ReplaceAllString(s, "$1=<hidden>")
}

func (d *debugRT) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Fprintf(d.w, "> %s %s\n", req.Method, req.URL.Path)
	resp, err := d.next.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(d.w, "< error: %v\n", err)
		return nil, err
	}
	fmt.Fprintf(d.w, "< HTTP %d  content-type=%s\n", resp.StatusCode, resp.Header.Get("Content-Type"))
	for _, sc := range resp.Header.Values("Set-Cookie") {
		name, _, _ := strings.Cut(sc, "=")
		fmt.Fprintf(d.w, "<   set-cookie %s (value hidden)\n", name)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		fmt.Fprintf(d.w, "<   location %s\n", redactSecrets(loc))
	}
	// Only small, non-XML bodies (logincheck answers) are worth printing.
	if strings.HasSuffix(req.URL.Path, "/logincheck") {
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(b))
		if rerr == nil {
			fmt.Fprintf(d.w, "<   body: %s\n", snippet(redactSecrets(string(b)), 500))
		}
	}
	return resp, nil
}
