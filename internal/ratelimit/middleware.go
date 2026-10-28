package ratelimit

import (
	"log"
	"net"
	"net/http"
)

type Allower interface {
	Allow(key string) bool
}

func Middleware(next http.Handler, l Allower) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		if !l.Allow(ip) {
			log.Printf("RATE LIMITED %s %s from %s", r.Method, r.URL.RequestURI(), ip)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
