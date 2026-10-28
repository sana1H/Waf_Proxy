package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	target := flag.String("url", "http://localhost:8080/rest/products/search?q=apple", "URL to test")
	total := flag.Int("n", 2000, "total requests")
	workers := flag.Int("c", 10, "concurrent workers")
	flag.Parse()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{MaxIdleConnsPerHost: *workers},
	}

	perWorker := *total / *workers
	results := make([][]time.Duration, *workers)
	notOK := make([]int, *workers)

	var wg sync.WaitGroup
	start := time.Now()
	var done atomic.Int64
	go func() {
		for {
			time.Sleep(time.Second)
			fmt.Printf("  ...%d/%d done\n", done.Load(), *total)
		}
	}()

	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				t0 := time.Now()
				resp, err := client.Get(*target)
				if err != nil {
					log.Printf("request failed: %v", err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					notOK[id]++
				}
				done.Add(1)
				results[id] = append(results[id], time.Since(t0))
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	var all []time.Duration
	bad := 0
	for id := range results {
		all = append(all, results[id]...)
		bad += notOK[id]
	}
	if len(all) == 0 {
		log.Fatal("no successful requests")
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	pct := func(p float64) time.Duration { return all[int(float64(len(all)-1)*p)] }

	fmt.Printf("requests: %d   non-200: %d   time: %v\n", len(all), bad, elapsed.Round(time.Millisecond))
	fmt.Printf("throughput: %.0f req/s\n", float64(len(all))/elapsed.Seconds())
	fmt.Printf("latency  p50: %v   p95: %v   p99: %v\n", pct(0.50), pct(0.95), pct(0.99))
}
