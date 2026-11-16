package testutil

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
)

// ClientHello holds the parts of a TLS ClientHello that middleboxes look at.
type ClientHello struct {
	Extensions           []uint16
	SupportedVersions    []uint16
	SupportedGroups      []uint16
	SignatureSchemes     []uint16
	SignatureSchemesCert []uint16
	ALPN                 []string
}

const (
	extSupportedGroups       = 10
	extSignatureAlgorithms   = 13
	extALPN                  = 16
	extSupportedVersions     = 43
	extSignatureAlgsCert     = 50
	recordTypeHandshake      = 22
	handshakeTypeClientHello = 1
)

var errMalformedHello = errors.New("malformed ClientHello")

// ParseClientHello parses a single TLS handshake record holding a ClientHello.
func ParseClientHello(record []byte) (*ClientHello, error) {
	if len(record) < 9 || record[0] != recordTypeHandshake || record[5] != handshakeTypeClientHello {
		return nil, errMalformedHello
	}
	r := newReader(record[9:])
	r.skip(2 + 32)  // legacy_version, random
	r.skip(r.u8())  // session_id
	r.skip(r.n16()) // cipher_suites
	r.skip(r.u8())  // compression_methods
	exts := r.sub(r.n16())
	h := &ClientHello{}
	for !exts.empty() {
		typ := exts.u16()
		body := exts.sub(exts.n16())
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case extSupportedGroups:
			h.SupportedGroups = body.list16(body.n16())
		case extSignatureAlgorithms:
			h.SignatureSchemes = body.list16(body.n16())
		case extSignatureAlgsCert:
			h.SignatureSchemesCert = body.list16(body.n16())
		case extSupportedVersions:
			h.SupportedVersions = body.list16(body.u8())
		case extALPN:
			list := body.sub(body.n16())
			for !list.empty() {
				h.ALPN = append(h.ALPN, string(list.take(list.u8())))
			}
			body.err = body.err || list.err
		}
		if body.err {
			exts.err = true
		}
	}
	if r.err || exts.err {
		return nil, errMalformedHello
	}
	return h, nil
}

// reader is a bounds-checked byte cursor. An out-of-range read marks it bad
// and returns zero values, so the caller checks once at the end.
type reader struct {
	b   []byte
	err bool
}

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) empty() bool { return r.err || len(r.b) == 0 }

func (r *reader) take(n int) []byte {
	if r.err || n < 0 || n > len(r.b) {
		r.err = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) u8() int {
	if b := r.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

// n16 reads a 16-bit length prefix.
func (r *reader) n16() int { return int(r.u16()) }

func (r *reader) sub(n int) *reader {
	s := newReader(r.take(n))
	s.err = r.err
	return s
}

func (r *reader) list16(n int) []uint16 {
	s := r.sub(n)
	var out []uint16
	for !s.empty() {
		out = append(out, s.u16())
	}
	if s.err {
		r.err = true
	}
	return out
}

// HelloProxy is an HTTP CONNECT proxy that reads the ClientHello of every
// tunnel. Tunnels the filter accepts are forwarded to Upstream (or closed when
// Upstream is empty). Tunnels it rejects are held open without a reply, the
// way a middlebox that drops the handshake behaves.
type HelloProxy struct {
	URL      *url.URL
	Upstream string

	mu     sync.Mutex
	hellos []*ClientHello
}

// Hellos returns the ClientHellos seen so far.
func (p *HelloProxy) Hellos() []*ClientHello {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.hellos)
}

// NewHelloProxy starts a HelloProxy. filter may be nil to accept everything.
func NewHelloProxy(t *testing.T, upstream string, filter func(*ClientHello) bool) *HelloProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &HelloProxy{URL: &url.URL{Scheme: "http", Host: ln.Addr().String()}, Upstream: upstream}
	done := make(chan struct{})
	var conns sync.WaitGroup
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		conns.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				defer c.Close() //nolint:errcheck // test proxy
				p.serve(c, filter, done)
			}()
		}
	}()
	return p
}

func (p *HelloProxy) serve(c net.Conn, filter func(*ClientHello) bool, done <-chan struct{}) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	record := make([]byte, 5+int(binary.BigEndian.Uint16(header[3:5])))
	copy(record, header)
	if _, err := io.ReadFull(br, record[5:]); err != nil {
		return
	}
	hello, err := ParseClientHello(record)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.hellos = append(p.hellos, hello)
	p.mu.Unlock()

	if filter != nil && !filter(hello) {
		closed := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, br); close(closed) }()
		select {
		case <-done:
		case <-closed:
		}
		return
	}
	if p.Upstream == "" {
		return
	}
	up, err := net.Dial("tcp", p.Upstream)
	if err != nil {
		return
	}
	if _, err := up.Write(record); err != nil {
		_ = up.Close()
		return
	}
	upClosed := make(chan struct{})
	go func() { _, _ = io.Copy(c, up); _ = c.Close(); close(upClosed) }()
	downClosed := make(chan struct{})
	go func() { _, _ = io.Copy(up, br); _ = up.Close(); close(downClosed) }()
	select {
	case <-done:
	case <-downClosed:
	}
	_ = c.Close()
	_ = up.Close()
	<-upClosed
	<-downClosed
}
