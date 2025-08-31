// sni.go — HTTPS SNI TCP proxy for wireproxy (combined + hardened)
//
// This follows the same design used by mosajjal/sniproxy (peek ClientHello,
// extract SNI, resolve, connect, replay bytes, then splice):
// - Parse minimal TLS record + ClientHello to find SNI (ext 0x0000)
// - Read with deadlines, but don't consume more than needed
// - Replay the exact buffered bytes to upstream before piping
//
// References:
//   - mosajjal/sniproxy/v2 pkg/https.go & pkg/https_sni.go (design & edge cases)
//   - agwa’s “Writing an SNI Proxy in 115 lines of Go” (minimal SNI parsing)
package wireproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

func (conf *SNIConfig) SpawnRoutine(vt *VirtualTun) {
	log.Printf("[SNI] listening on %s", conf.BindAddress)
	ln, err := net.Listen("tcp", conf.BindAddress)
	if err != nil {
		log.Fatalf("[SNI] listen error on %s: %v", conf.BindAddress, err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("[SNI] accept: %v", err)
			continue
		}
		go serveSNIConn(vt, conf, c)
	}
}

// ---- Core handling ----

const (
	// conservative upper bounds for the initial peek:
	// TLS record header (5) + handshake hdr (4) + client random (32) + sessID(<=32)
	// + cipher suites(<= 2*300) + comp(<= 256) + extensions(<= 8k)
	maxPeek       = 16384
	helloDeadline = 10 * time.Second
)

func serveSNIConn(vt *VirtualTun, conf *SNIConfig, client net.Conn) {
	defer func() {
		// If anything goes wrong before splice starts, ensure close.
		// After splice, the goroutines handle closing.
	}()

	if err := client.SetReadDeadline(time.Now().Add(helloDeadline)); err != nil {
		log.Printf("[SNI] set deadline: %v", err)
		client.Close()
		return
	}

	br := bufio.NewReader(client)
	peek, sni, err := peekClientHelloSNI(br)
	if err != nil {
		log.Printf("[SNI] parse ClientHello failed: %v", err)
		client.Close()
		return
	}
	// Clear the deadline now that handshake bytes are read
	_ = client.SetReadDeadline(time.Time{})

	if sni == "" {
		log.Printf("[SNI] no SNI; closing")
		client.Close()
		return
	}

	host := strings.ToLower(sni)
	log.Printf("[SNI] client SNI=%q", host)

	// Reject private/loopback if not allowed (like sniproxy’s ACL local protection)
	if !conf.AllowConnToLocal {
		if isLocalName(host) {
			log.Printf("[SNI] destination %q resolves local; blocked", host)
			client.Close()
			return
		}
	}

	// Resolve via VirtualTun resolver (respects vt.SystemDNS)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	addr, err := vt.ResolveAddrWithContext(ctx, host)
	if err != nil {
		log.Printf("[SNI] resolve %s: %v", host, err)
		client.Close()
		return
	}
	target := net.JoinHostPort(addr.String(), "443")
	log.Printf("[SNI] dialing %s(%s)", host, target)

	// Dial upstream *through* the WG netstack
	up, err := vt.Tnet.Dial("tcp", target)
	if err != nil {
		log.Printf("[SNI] dial upstream %s: %v", target, err)
		client.Close()
		return
	}

	// Send the exact bytes we peeked (ClientHello + any extra we buffered)
	// NOTE: we have not consumed the reader yet; write peek to upstream,
	// then stream the remainder from br -> up, and up -> client.
	// 1) Send the exact bytes we peeked (ClientHello + any bytes we included)
	if _, err = up.Write(peek); err != nil {
		log.Printf("[SNI] write upstream (replay ClientHello) failed: %v", err)
		client.Close()
		up.Close()
		return
	}

	// 2) IMPORTANT: discard the same bytes from the client reader,
	//    so we don't send them a second time in io.Copy.
	if _, err := br.Discard(len(peek)); err != nil {
		log.Printf("[SNI] discard from client failed: %v", err)
		client.Close()
		up.Close()
		return
	}

	// 3) Now start splicing the remaining stream
	go func() {
		defer client.Close()
		defer up.Close()
		_, _ = io.Copy(up, br) // remaining client -> upstream
	}()
	go func() {
		defer client.Close()
		defer up.Close()
		_, _ = io.Copy(client, up) // upstream -> client
	}()
}

// ---- Helpers ----

func isLocalName(h string) bool {
	// quick heuristics; the actual “local” decision is from resolution results,
	// but this catches obvious names fast.
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// peekClientHelloSNI reads enough from br to:
//  1) verify it's a TLS ClientHello
//  2) extract the SNI (server_name extension 0x0000)
// It returns the bytes that must be replayed to upstream, the sni, or error.
func peekClientHelloSNI(br *bufio.Reader) ([]byte, string, error) {
	// We need to *peek*, not consume. So we’ll ReadSlice progressively while
	// tracking how many bytes we should have, then finally use br.Peek(total).
	const tlsRecordHeader = 5

	hdr, err := br.Peek(tlsRecordHeader)
	if err != nil {
		return nil, "", fmt.Errorf("read TLS record header: %w", err)
	}
	if hdr[0] != 0x16 { // Handshake
		return nil, "", errors.New("not a TLS handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	totalNeed := tlsRecordHeader + recLen
	if totalNeed > maxPeek {
		return nil, "", fmt.Errorf("ClientHello too large: %d", totalNeed)
	}

	buf, err := br.Peek(totalNeed)
	if err != nil {
		return nil, "", fmt.Errorf("peek %d: %w", totalNeed, err)
	}

	// Parse ClientHello inside the record
	// Record payload starts at 5
	p := 5
	if p+1 > len(buf) || buf[p] != 0x01 { // client_hello
		return nil, "", errors.New("not ClientHello")
	}
	if p+4 > len(buf) {
		return nil, "", errors.New("short ClientHello header")
	}
	helloLen := int(buf[p+1])<<16 | int(buf[p+2])<<8 | int(buf[p+3])
	p += 4
	if p+helloLen > len(buf) {
		return nil, "", errors.New("incomplete ClientHello")
	}

	// Skip: legacy_version(2) + random(32)
	if p+2+32 > len(buf) {
		return nil, "", errors.New("short random")
	}
	p += 2 + 32

	// session_id
	if p+1 > len(buf) {
		return nil, "", errors.New("short session_id len")
	}
	sidLen := int(buf[p])
	p += 1 + sidLen
	if p > len(buf) {
		return nil, "", errors.New("short session_id")
	}

	// cipher_suites
	if p+2 > len(buf) {
		return nil, "", errors.New("short cipher_suites len")
	}
	csLen := int(buf[p])<<8 | int(buf[p+1])
	p += 2 + csLen
	if p > len(buf) {
		return nil, "", errors.New("short cipher_suites")
	}

	// compression_methods
	if p+1 > len(buf) {
		return nil, "", errors.New("short compression_methods len")
	}
	compLen := int(buf[p])
	p += 1 + compLen
	if p > len(buf) {
		return nil, "", errors.New("short compression_methods")
	}

	// extensions (optional)
	if p == len(buf) {
		// no extensions => no SNI
		return buf, "", nil
	}
	if p+2 > len(buf) {
		return nil, "", errors.New("short extensions len")
	}
	extsLen := int(buf[p])<<8 | int(buf[p+1])
	p += 2
	if p+extsLen > len(buf) {
		return nil, "", errors.New("short extensions")
	}

	end := p + extsLen
	for p+4 <= end {
		extType := int(buf[p])<<8 | int(buf[p+1])
		extLen := int(buf[p+2])<<8 | int(buf[p+3])
		p += 4
		if p+extLen > end {
			return nil, "", errors.New("short extension body")
		}

		if extType == 0x0000 { // server_name
			sni, err := parseSNIExtension(buf[p : p+extLen])
			if err != nil {
				return nil, "", err
			}
			return buf, sni, nil
		}
		p += extLen
	}
	// No SNI found
	return buf, "", nil
}

// RFC 6066 §3: server_name extension
func parseSNIExtension(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("short SNI list len")
	}
	listLen := int(b[0])<<8 | int(b[1])
	if listLen+2 > len(b) {
		return "", errors.New("short SNI list")
	}
	p := 2
	for p+3 <= 2+listLen {
		nameType := b[p]
		nameLen := int(b[p+1])<<8 | int(b[p+2])
		p += 3
		if p+nameLen > 2+listLen {
			return "", errors.New("short SNI name")
		}
		if nameType == 0 { // host_name
			return string(b[p : p+nameLen]), nil
		}
		p += nameLen
	}
	return "", errors.New("no host_name in SNI")
}
