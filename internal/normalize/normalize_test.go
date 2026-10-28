package normalize

import "testing"

func TestDecode(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		want       string
		suspicious bool
	}{
		{"plain text", "apple", "apple", false},
		{"single encoded", "%27%20OR", "' OR", false},
		{"double encoded", "%2527%2520OR", "' OR", false},
		{"null byte trick", "<scr%00ipt>", "<script>", false},
		{"stray percent", "100%", "100%", false},
		{"six layers", "%252525252527", "%27", true},
		{"overlong slash", "..%c0%af", "../", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, susp := Decode(tt.input)
			if got != tt.want || susp != tt.suspicious {
				t.Errorf("Decode(%q) = (%q, %v), want (%q, %v)",
					tt.input, got, susp, tt.want, tt.suspicious)
			}
		})
	}
}
