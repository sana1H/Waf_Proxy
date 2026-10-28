# waf-proxy

A small web application firewall (WAF) written in Go. It sits in front of a web app as a reverse proxy, inspects every request, and blocks common attacks (SQL injection, XSS, path traversal) before they reach the app. It also rate-limits clients per IP.

This is a learning project. It is tested against [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), a deliberately vulnerable app. **Only test it against systems you own.**

## How it works

```
client --> rate limiter --> WAF rules --> reverse proxy --> backend app
           (per IP)         (decode, then match)

           429 Too Many     403 Forbidden
           Requests         (or log-only)
```

1. **Rate limiter** (cheapest check, so it runs first): a per-IP token bucket. Each request costs one token, tokens refill over time, an empty bucket gets `429`.
2. **Normalization:** each input (URL path and every query parameter value) is URL-decoded repeatedly until it stops changing, so `%2527` cannot hide a `'`. Null bytes and overlong-UTF-8 slashes are cleaned. More than 5 rounds of decoding is treated as an attack (`EncodingAbuse`).
3. **Rules:** regular-expression signatures run on the *decoded* text. A match returns `403`, or is only logged in log-only mode.
4. **Reverse proxy:** clean requests are forwarded with Go's `httputil.ReverseProxy`.

### Rules

| Rule | Catches |
|---|---|
| `SQLi-tautology` | `OR 1=1`, `' OR 'a'='a`, `') OR ('1'='1` |
| `SQLi-comment` | `'--`, a digit or bracket followed by `-- `, `'#` |
| `SQLi-union` | `UNION SELECT <columns>`, including `UNION/**/SELECT` |
| `SQLi-stacked` | `; DROP TABLE ...` and similar |
| `SQLi-time` | `SLEEP(n)`, `BENCHMARK(n)` |
| `XSS-tag` | `<script`, `<iframe`, `<object`, `<embed` |
| `XSS-handler` | any `on...=` attribute (`onerror=`, `onfocus=`, ...) |
| `XSS-javascript-url` | `javascript:` followed by a function call |
| `PathTraversal` | `../` and `..\` |
| `SensitiveFile` | `/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini` |

Rules are narrow on purpose. Broad rules (for example, blocking every `--`) block innocent users, which is a false positive.

### Modes

- `block` (default): matching requests get `403`.
- `log`: matching requests are logged as `DETECTED` and still forwarded. Use this to watch for false positives before turning blocking on.

## Run it

Requirements: Go 1.22 or newer, and Docker.

```
# 1. start the vulnerable target on :3000
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop

# 2. start the WAF on :8080
go run ./cmd/waf

# 3. try it
curl -i "http://localhost:8080/rest/products/search?q=apple"
curl -i "http://localhost:8080/rest/products/search?q=%27%20OR%201%3D1--"
```

The first request returns products. The second returns `403 Blocked by WAF`.

Options:

| Flag | Default | Meaning |
|---|---|---|
| `-mode` | `block` | `block` or `log` |
| `-rate` | `50` | allowed requests per second per IP |
| `-burst` | `100` | burst size per IP |

The backend address is currently fixed to `http://localhost:3000` in `cmd/waf/main.go`.

## Project layout

```
cmd/
  waf/     the proxy
  eval/    measures detection rate and false positives
  bench/   measures latency and throughput
internal/
  proxy/       reverse proxy wrapper
  waf/         rules and middleware (+ benchmark)
  normalize/   repeated decoding and cleanup (+ tests)
  ratelimit/   per-IP token bucket and middleware (+ tests)
testdata/      attack and benign payload files
```

## Results

All numbers come from runs on one machine: AMD Ryzen 5 7530U, Go 1.26, Windows, Juice Shop in Docker on the same machine.

### Detection

`cmd/eval` sends each payload as a URL-encoded search query and counts `403` responses. Benign payloads include hard cases such as `O'Brien`, `well--done`, and `labor union select committee`.

| Set | Rules | Detected | False positives |
|---|---|---|---|
| Practice (35 attacks, 27 benign) | v1 | 25/35 (71.4%) | 3/27 (11.1%) |
| Practice | v2 | 35/35 | 0/27 |
| **Held-out (24 attacks, 20 benign)** | v1 | 13/24 (54.2%) | 2/20 (10%) |
| **Held-out** | v2 | **19/24 (79.2%)** | **1/20 (5%)** |

By category on the held-out set (v1 to v2): SQLi 5/10 to 8/10, XSS 4/7 to 5/7, path traversal 2/5 to 4/5, double-encoded 2/2 to 2/2.

How to read this:
- The v2 rules were written from the practice-set misses, so the practice-set result for v2 is not independent evidence.
- The held-out set was not used to tune v2. It is the number to trust.
- Both sets are small and hand-written. 19/24 is indicative, not a benchmark.

### Performance

**Inspection cost** (Go benchmark of the middleware alone, benign request, block mode):

```
BenchmarkMiddleware-12   70610   16110 ns/op   613 B/op   7 allocs/op
```

That is about 16 microseconds per request for decoding plus all rules.

**End to end** (`cmd/bench`, 100 requests per run, Juice Shop vs through the proxy):

| Workers | Target | p50 | p95 | p99 | Throughput |
|---|---|---|---|---|---|
| 1 | direct | 56.3 ms | 70.3 ms | 97.8 ms | 17 req/s |
| 1 | via proxy | 57.2 ms | 100.3 ms | 145.8 ms | 16 req/s |
| 4 | direct | 231.5 ms | 245.6 ms | 248.3 ms | 17 req/s |
| 4 | via proxy | 224.5 ms | 283.4 ms | 316.8 ms | 17 req/s |

How to read this:
- Juice Shop itself saturates at about 17 req/s, so it is the bottleneck. With 4 workers each request waits behind the others (about 4 x 57 ms).
- Median overhead of the proxy is about 1 ms, which is within noise (at 4 workers the proxy run was faster).
- With 100 requests, p95 and p99 are dominated by a few slow requests. They do not show whether the proxy really affects tail latency.
- This test cannot measure the proxy's own maximum throughput, because the backend limits it first.

## Run the tests and measurements

```
go test ./...
go test -bench . -benchmem ./internal/waf

go run ./cmd/waf -rate 100000 -burst 100000        # terminal 1 (limiter effectively off)
go run ./cmd/eval                                   # terminal 2: practice set
go run ./cmd/eval -attacks testdata/attacks_holdout.txt -benign testdata/benign_holdout.txt
go run ./cmd/bench -url http://localhost:8080/rest/products/search?q=apple -n 100 -c 1
```

## Known limitations

- **Only the URL path and query values are inspected.** Request bodies (including JSON login forms), headers, cookies, and parameter names are not. Many real injection attacks arrive in POST bodies, so this is the biggest gap.
- **Signature rules can be evaded.** Remaining misses on the held-out set: `' OR ''='`, `' || (SELECT 1) || '`, `<style>@import ...`, `'-alert(1)-'`, `/proc/self/environ`.
- **Context-dependent attacks are out of reach for regexes.** `'-alert(1)-'` has no HTML tag; it only works inside an existing JavaScript string. The real fix for these is in the app (output encoding, Content-Security-Policy). A WAF is one layer of defense, not a substitute for fixing the app.
- **Known false positive:** a digit followed by `-- ` (for example `pack of 6 -- discount`) looks like an SQL comment and is blocked.
- **Rate limiter is in-memory and per process.** It does not share state across instances, keys on the direct connection IP (it deliberately ignores `X-Forwarded-For`, which a client can fake, so it is wrong behind a load balancer), and never evicts idle buckets, so memory grows with the number of distinct IPs.
- **Single fixed backend, plain HTTP.** No TLS, and responses are not inspected.
- **Measurement limits:** small hand-written test sets, one machine, and a backend that is slower than the proxy (see above).

## Ideas for next steps

- Inspect request bodies and headers.
- Evict idle rate-limit buckets; plug in a shared (Redis-backed) limiter through the `Allower` interface in `internal/ratelimit`.
- Add a `-target` flag for the backend address.
- Test against a larger, independently written payload set.