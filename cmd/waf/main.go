package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/sana1H/waf-proxy/internal/proxy"
	"github.com/sana1H/waf-proxy/internal/ratelimit"
	"github.com/sana1H/waf-proxy/internal/waf"
)

func main() {
	mode := flag.String("mode", "block", "block or log")
	rate := flag.Float64("rate", 50, "allowed requests per second per IP")
	burst := flag.Float64("burst", 100, "burst size per IP")
	flag.Parse()

	p, err := proxy.New("http://localhost:3000")
	if err != nil {
		log.Fatal(err)
	}

	limiter := ratelimit.New(*rate, *burst)
	handler := ratelimit.Middleware(waf.Middleware(p, *mode), limiter)

	log.Printf("WAF listening on :8080 (mode=%s, rate=%.0f/s, burst=%.0f)", *mode, *rate, *burst)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
