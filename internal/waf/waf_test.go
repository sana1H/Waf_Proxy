package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkMiddleware(b *testing.B) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := Middleware(next, "block")
	req := httptest.NewRequest("GET", "/rest/products/search?q=apple", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
}
