package normalize

import (
	"net/url"
	"strings"
)

const maxRounds = 5

func Decode(s string) (string, bool) {
	for i := 0; i < maxRounds; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return clean(s), false
		}
		s = decoded
	}
	return clean(s), true
}

func clean(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\xc0\xaf", "/")
	s = strings.ReplaceAll(s, "\xc1\x9c", `\`)
	return s
}
