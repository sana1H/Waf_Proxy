package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type result struct {
	total   int
	blocked int
}

func main() {
	target := flag.String("target", "http://localhost:8080", "WAF address")
	attacksFile := flag.String("attacks", "testdata/attacks.txt", "attack payload file")
	benignFile := flag.String("benign", "testdata/benign.txt", "benign payload file")
	flag.Parse()

	attackLines, err := readLines(*attacksFile)
	if err != nil {
		log.Fatal(err)
	}
	benignLines, err := readLines(*benignFile)
	if err != nil {
		log.Fatal(err)
	}

	stats := map[string]*result{}
	var order []string
	var missed []string

	for _, line := range attackLines {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			log.Fatalf("bad line in attacks file: %q", line)
		}
		category, payload := parts[0], parts[1]

		code := send(*target, payload)
		r, ok := stats[category]
		if !ok {
			r = &result{}
			stats[category] = r
			order = append(order, category)
		}
		r.total++
		if code == http.StatusForbidden {
			r.blocked++
		} else {
			missed = append(missed, category+"  "+payload)
		}
	}

	fpBlocked := 0
	var falsePositives []string
	for _, payload := range benignLines {
		if send(*target, payload) == http.StatusForbidden {
			fpBlocked++
			falsePositives = append(falsePositives, payload)
		}
	}

	fmt.Println("DETECTION BY CATEGORY")
	totalAttacks, totalBlocked := 0, 0
	for _, category := range order {
		r := stats[category]
		fmt.Printf("  %-15s %2d/%-2d blocked (%.0f%%)\n",
			category, r.blocked, r.total, 100*float64(r.blocked)/float64(r.total))
		totalAttacks += r.total
		totalBlocked += r.blocked
	}

	fmt.Printf("\nOVERALL detection rate: %d/%d (%.1f%%)\n",
		totalBlocked, totalAttacks, 100*float64(totalBlocked)/float64(totalAttacks))
	fmt.Printf("FALSE POSITIVE rate:    %d/%d (%.1f%%)\n",
		fpBlocked, len(benignLines), 100*float64(fpBlocked)/float64(len(benignLines)))

	fmt.Println("\nMISSED ATTACKS:")
	for _, m := range missed {
		fmt.Println("  ", m)
	}
	fmt.Println("\nFALSE POSITIVES (innocent requests blocked):")
	for _, f := range falsePositives {
		fmt.Println("  ", f)
	}
}

func send(target, payload string) int {
	u := target + "/rest/products/search?q=" + url.QueryEscape(payload)
	resp, err := http.Get(u)
	if err != nil {
		log.Fatalf("request failed (is the WAF running?): %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		log.Fatal("got 429: restart the WAF with -rate=100000 -burst=100000")
	}
	return resp.StatusCode
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
