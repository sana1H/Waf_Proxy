package ratelimit

import "testing"

func TestAllow(t *testing.T) {
	l := New(0.001, 3)

	for i := 1; i <= 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th request should be blocked")
	}
	if !l.Allow("b") {
		t.Fatal("a different key should have its own bucket")
	}
}
