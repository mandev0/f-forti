package forti

import (
	"html"
	"regexp"
	"strings"
)

var (
	reInput = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reAttr  = regexp.MustCompile(`(?is)\b(name|value|type)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
)

// parseLegacyChallenge handles older FortiOS versions that answer the first
// logincheck with an HTML form containing hidden fields and a token input.
func parseLegacyChallenge(body string) *Challenge {
	low := strings.ToLower(body)
	if !strings.Contains(low, "<form") || !strings.Contains(low, "magic") {
		return nil
	}
	ch := &Challenge{legacy: true, Fields: map[string]string{}, Message: "Enter the verification code"}
	for _, tag := range reInput.FindAllString(body, -1) {
		var name, value, typ string
		for _, m := range reAttr.FindAllStringSubmatch(tag, -1) {
			v := m[3] + m[4] + m[5]
			switch strings.ToLower(m[1]) {
			case "name":
				name = v
			case "value":
				value = html.UnescapeString(v)
			case "type":
				typ = strings.ToLower(v)
			}
		}
		if name == "" || typ == "submit" || typ == "button" {
			continue
		}
		ch.inputs = append(ch.inputs, kv{name, value})
		ch.Fields[name] = value
		if ch.codeField == "" && (typ == "password" || name == "code") {
			ch.codeField = name
		}
	}
	if ch.codeField == "" {
		return nil
	}
	return ch
}
