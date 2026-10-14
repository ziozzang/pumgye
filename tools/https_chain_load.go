// Owned HTTPS chain load generator: credentials enter only through the environment.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	serve := flag.String("serve", "", "owned origin listen address")
	expected := flag.String("subject", "", "owned expected subject")
	origin := flag.String("origin", "", "owned HTTPS origin")
	ca := flag.String("ca", "", "owned CA file")
	workers := flag.Int("workers", 16, "workers")
	seconds := flag.Int("seconds", 10, "duration")
	flag.Parse()
	if *serve != "" {
		if *expected == "" {
			panic("owned subject required")
		}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-Forwarded-User") != *expected || r.Header.Get("X-Hopae-Aal") != "0" || r.Header.Get("X-Hopae-Principal-Kind") != "service" || r.Header.Get("X-Hopae-Service-Id") != "logs" {
				http.Error(w, "owned origin identity refused", 400)
				return
			}
			w.Header().Set("Content-Length", "2")
			w.Write([]byte("ok"))
		})
		if err := http.ListenAndServe(*serve, nil); err != nil {
			panic("owned origin failed")
		}
		return
	}
	if *workers < 1 || *workers > 64 || *seconds < 1 || *seconds > 60 || os.Getenv("OWNED_CHAIN_TOKEN") == "" {
		panic("invalid owned load arguments")
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		panic("owned CA read failed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("owned CA invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxIdleConns: *workers, MaxIdleConnsPerHost: *workers, MaxConnsPerHost: *workers, ForceAttemptHTTP2: false}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	token := os.Getenv("OWNED_CHAIN_TOKEN")
	start := time.Now()
	deadline := start.Add(time.Duration(*seconds) * time.Second)
	var wait sync.WaitGroup
	var lock sync.Mutex
	var samples []int64
	statuses := map[int]int{}
	failures := 0
	for i := 0; i < *workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			local := []int64{}
			counts := map[int]int{}
			failed := 0
			for time.Now().Before(deadline) {
				request, err := http.NewRequest("GET", *origin+"/secure", nil)
				if err != nil {
					panic("owned origin invalid")
				}
				request.Host = "app.example.test"
				request.Header.Set("Authorization", "Bearer "+token)
				began := time.Now()
				response, err := client.Do(request)
				if err != nil {
					failed++
					continue
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
				response.Body.Close()
				counts[response.StatusCode]++
				if err == nil && response.StatusCode == 200 && string(body) == "ok" {
					local = append(local, time.Since(began).Microseconds())
				} else {
					failed++
				}
			}
			lock.Lock()
			samples = append(samples, local...)
			for code, n := range counts {
				statuses[code] += n
			}
			failures += failed
			lock.Unlock()
		}()
	}
	wait.Wait()
	elapsed := time.Since(start).Seconds()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50, p99 := int64(0), int64(0)
	if len(samples) > 0 {
		p50 = samples[len(samples)/2]
		p99 = samples[(len(samples)-1)*99/100]
	}
	result := map[string]interface{}{"verified_responses": len(samples), "elapsed_seconds": elapsed, "verified_qps": float64(len(samples)) / elapsed, "p50_us": p50, "p99_us": p99, "workers": *workers, "failures": failures, "statuses": statuses, "load": "closed-loop HTTPS, native HOP1/PPG1/HGD1 mTLS, native API key"}
	encoded, _ := json.Marshal(result)
	fmt.Println(string(encoded))
	transport.CloseIdleConnections()
	if failures > 0 {
		os.Exit(1)
	}
}
