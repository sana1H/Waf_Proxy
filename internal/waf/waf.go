package waf

import (
	"log"
	"net/http"
	"regexp"

	"github.com/sana1H/waf-proxy/internal/normalize"
)

type Rule struct {
	Name    string
	Pattern *regexp.Regexp
}

// var rules = []Rule{
// 	{"SQLi", regexp.MustCompile(`(?i)(\bor\b\s+\d+\s*=\s*\d+|'\s*--|--\s|--$|union\s+select)`)},
// 	{"XSS", regexp.MustCompile(`(?i)(<script|javascript:|onerror\s*=|onload\s*=)`)},
// 	{"PathTraversal", regexp.MustCompile(`\.\.[/\\]`)},
// }
var rules = []Rule{
	{"SQLi-tautology", regexp.MustCompile(`(?i)(\b(or|and)\s+\d+\s*=\s*\d+|['"]\)?\s*(or|and)\s+\(?['"]?\w+['"]?\s*=\s*['"]?\w+)`)},
	{"SQLi-comment", regexp.MustCompile(`(?i)(['")\d;]\s*--(\s|$)|['"]\s*#)`)},
	{"SQLi-union", regexp.MustCompile(`(?i)union(\s|/\*.*?\*/)+(all\s+)?select\s+(null|\d|\*|@@|[\w.]+\s*,|[\w.]+\s+from\b)`)},
	{"SQLi-stacked", regexp.MustCompile(`(?i);\s*(drop|delete|insert|update|alter|create|shutdown)\b`)},
	{"SQLi-time", regexp.MustCompile(`(?i)\b(sleep|benchmark)\s*\(\s*\d`)},
	{"XSS-tag", regexp.MustCompile(`(?i)<\s*(script|iframe|object|embed)\b`)},
	{"XSS-handler", regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)},
	{"XSS-javascript-url", regexp.MustCompile(`(?i)javascript:\s*[\w.]+\s*\(`)},
	{"PathTraversal", regexp.MustCompile(`\.\.[/\\]`)},
	{"SensitiveFile", regexp.MustCompile(`(?i)(/etc/(passwd|shadow)|\\windows\\|win\.ini|boot\.ini)`)},
}

func check(input string) (string, bool) {
	for _, rule := range rules {
		if rule.Pattern.MatchString(input) {
			return rule.Name, true
		}
	}
	return "", false
}

func Middleware(next http.Handler, mode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inputs := []string{r.URL.Path}
		for _, values := range r.URL.Query() {
			inputs = append(inputs, values...)
		}

		for _, input := range inputs {
			decoded, suspicious := normalize.Decode(input)
			name, bad := check(decoded)
			if suspicious {
				name, bad = "EncodingAbuse", true
			}
			if bad {
				if mode == "block" {
					log.Printf("BLOCKED %s %s (%s rule)", r.Method, r.URL.RequestURI(), name)
					http.Error(w, "Blocked by WAF", http.StatusForbidden)
					return
				}
				log.Printf("DETECTED (log-only) %s %s (%s rule)", r.Method, r.URL.RequestURI(), name)
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}
