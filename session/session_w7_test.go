package session

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/IFindMe/open-upp/identity"
	"github.com/IFindMe/open-upp/spec"
)

func wantFailureToken(t *testing.T, err error, token string) {
	t.Helper()
	var f *spec.Failure
	if !errors.As(err, &f) {
		t.Fatalf("error %v is not *spec.Failure (want token %q)", err, token)
	}
	if f.Token != token {
		t.Fatalf("token = %q, want %q", f.Token, token)
	}
}

// ---- Area 2: freshness / single-use / transcript binding ----

func TestChallengeFreshSingleUseAndStale(t *testing.T) {
	challenge := bytes.Repeat([]byte{7}, 32)
	newH := func(age time.Duration) *handshake {
		return &handshake{challenge: [32]byte(challenge[:32]), issuedAt: time.Now().Add(-age)}
	}
	// Fresh, correct challenge succeeds once.
	h := newH(0)
	if err := h.checkChallenge(challenge); err != nil {
		t.Fatalf("fresh challenge rejected: %v", err)
	}
	// Replay of the same challenge in one handshake is stale/single-use.
	if err := h.checkChallenge(challenge); err == nil {
		t.Fatal("reused challenge accepted")
	} else {
		wantFailureToken(t, err, spec.StaleChallenge)
	}

	// A wrong challenge is rejected but does not consume the real one.
	h = newH(0)
	wrong := bytes.Repeat([]byte{8}, 32)
	if err := h.checkChallenge(wrong); err == nil {
		t.Fatal("wrong challenge accepted")
	} else {
		wantFailureToken(t, err, spec.StaleChallenge)
	}
	if err := h.checkChallenge(challenge); err != nil {
		t.Fatalf("real challenge unusable after wrong attempt: %v", err)
	}

	// Outside the 60 s freshness window is stale.
	h = newH(time.Duration(spec.FreshnessWindowS+1) * time.Second)
	if err := h.checkChallenge(challenge); err == nil {
		t.Fatal("stale (>60s) challenge accepted")
	} else {
		wantFailureToken(t, err, spec.StaleChallenge)
	}
}

func TestTranscriptHashAndPopBlobBinding(t *testing.T) {
	hello, resp := bytes.Repeat([]byte{1}, 40), bytes.Repeat([]byte{2}, 60)
	th := transcriptHash(hello, resp)
	if th != transcriptHash(hello, resp) {
		t.Fatal("transcript hash not deterministic")
	}
	if th == transcriptHash(bytes.Repeat([]byte{9}, 40), resp) {
		t.Fatal("transcript hash ignores HELLO bytes")
	}
	if th == transcriptHash(hello, bytes.Repeat([]byte{9}, 60)) {
		t.Fatal("transcript hash ignores HELLO_RESPONSE bytes")
	}

	cP, cL := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	eL, eP := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	blob := popBlob(cP, cL, eL, eP, th)
	if !bytes.Contains(blob, []byte(spec.TagHandshakePoP)) {
		t.Fatal("PoP blob missing handshake domain tag as field 0")
	}
	for i, mut := range [][][]byte{
		{bytes.Repeat([]byte{0}, 32), cL, eL, eP},
		{cP, bytes.Repeat([]byte{0}, 32), eL, eP},
		{cP, cL, bytes.Repeat([]byte{0}, 32), eP},
		{cP, cL, eL, bytes.Repeat([]byte{0}, 32)},
	} {
		if bytes.Equal(blob, popBlob(mut[0], mut[1], mut[2], mut[3], th)) {
			t.Fatalf("PoP blob ignores field mutation %d", i)
		}
	}
	th2 := th
	th2[0] ^= 0xff
	if bytes.Equal(blob, popBlob(cP, cL, eL, eP, th2)) {
		t.Fatal("PoP blob ignores transcript hash")
	}
}

// corruptWriteConn flips the last byte of the Nth framed write in transit.
type corruptWriteConn struct {
	net.Conn
	writes int
	target int
	at     int // byte offset within frame to flip; -1 = last byte
}

func (c *corruptWriteConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == c.target && len(b) > 4 {
		i := c.at
		if i < 0 || i >= len(b) {
			i = len(b) - 1
		}
		b[i] ^= 0xff
	}
	return c.Conn.Write(b)
}

func runHandshakePair(t *testing.T, wrapI, wrapR func(net.Conn) net.Conn) (*HandshakeResult, *HandshakeResult, error, error) {
	t.Helper()
	a, b := net.Pipe()
	ca, cb := net.Conn(a), net.Conn(b)
	if wrapI != nil {
		ca = wrapI(a)
	}
	if wrapR != nil {
		cb = wrapR(b)
	}
	alice, _ := identity.Create("device")
	bob, _ := identity.Create("device")
	var hr *HandshakeResult
	var er error
	done := make(chan struct{})
	go func() {
		hr, er = ResponderHandshake(cb, bob)
		close(done)
	}()
	hi, ei := InitiatorHandshake(ca, alice)
	if ei != nil {
		a.Close() // unblock the peer instead of waiting for the 10 s deadline
	}
	<-done
	if hi != nil && hr != nil {
		if hi.LocalFP != alice.Fingerprint() || hr.LocalFP != bob.Fingerprint() {
			t.Fatal("handshake peers mis-identified")
		}
	}
	return hi, hr, ei, er
}

func TestMutualPOPHandshakeHappyPath(t *testing.T) {
	hi, hr, ei, er := runHandshakePair(t, nil, nil)
	if ei != nil || er != nil {
		t.Fatalf("handshake failed: initiator=%v responder=%v", ei, er)
	}
	if hi.TH != hr.TH {
		t.Fatal("transcript hash differs between peers")
	}
	if hi.SNDigest != hr.SNDigest {
		t.Fatal("pairwise SN digest differs between peers")
	}
	if hi.PeerFP != hr.LocalFP || hr.PeerFP != hi.LocalFP {
		t.Fatal("peer fingerprints inconsistent")
	}
	if len(hi.ECDH) != 32 || len(hr.ECDH) != 32 || !bytes.Equal(hi.ECDH, hr.ECDH) {
		t.Fatal("ECDH shared secrets differ")
	}
	if hi.Role != RoleInitiator || hr.Role != RoleResponder {
		t.Fatal("roles assigned incorrectly")
	}
	// The handshake result holds no installed AEAD key; Derive is a separate step.
	if hi.SNDigest == [32]byte{} {
		t.Fatal("SN digest unexpectedly zero")
	}
}

func TestTamperedFinishedPoPRejected(t *testing.T) {
	// The initiator still completes its side after writing FINISHED; the
	// responder is the verifier that must reject the corrupted signature.
	hi, _, _, er := runHandshakePair(t, func(c net.Conn) net.Conn {
		return &corruptWriteConn{Conn: c, target: 2, at: -1} // FINISHED frame: corrupt signature
	}, nil)
	if hi == nil {
		t.Fatal("initiator did not finish its side of the handshake")
	}
	if er == nil {
		t.Fatal("tampered FINISHED PoP accepted by responder")
	}
	// A corrupted PoP signature maps to bad_proof, not a silent success.
	wantFailureToken(t, er, spec.BadProof)
}

func TestTamperedEphemeralInHelloResponseRejected(t *testing.T) {
	// HELLO_RESPONSE frame layout: 4 hdr + 1 type + Canon(version 5, suite 30,
	// challenge 36) => ephemeral value begins at frame offset 76. Flipping a
	// transcript-bound ephemeral byte must break the peer's PoP verification.
	_, _, ei, _ := runHandshakePair(t, nil, func(c net.Conn) net.Conn {
		return &corruptWriteConn{Conn: c, target: 1, at: 80}
	})
	if ei == nil {
		t.Fatal("tampered HELLO_RESPONSE ephemeral accepted")
	}
	wantFailureToken(t, ei, spec.BadProof)
}

func TestTamperedSuiteInHelloResponseRejected(t *testing.T) {
	// Corrupting the suite string is a downgrade/unknown-suite attempt and must
	// be refused with version_rejected, never a fallback.
	_, _, ei, _ := runHandshakePair(t, nil, func(c net.Conn) net.Conn {
		return &corruptWriteConn{Conn: c, target: 1, at: 26}
	})
	if ei == nil {
		t.Fatal("tampered suite accepted")
	}
	wantFailureToken(t, ei, spec.VersionRejected)
}

func TestLocalRevokedKeyFailsAtHandshake(t *testing.T) {
	id, _ := identity.Create("device")
	if err := id.RevokeKey(id.CurrentKey()); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := InitiatorHandshake(a, id)
	wantFailureToken(t, err, spec.Revoked)
}

// ---- Area 6: session AEAD ----

func pairedHandshakes(t *testing.T) (*HandshakeResult, *HandshakeResult) {
	t.Helper()
	hi, hr, ei, er := runHandshakePair(t, nil, nil)
	if ei != nil || er != nil {
		t.Fatalf("handshake failed: %v / %v", ei, er)
	}
	return hi, hr
}

func pairedSessions(t *testing.T) (*Session, *Session) {
	t.Helper()
	hi, hr := pairedHandshakes(t)
	si, err := hi.Derive("stream")
	if err != nil {
		t.Fatal(err)
	}
	sr, err := hr.Derive("stream")
	if err != nil {
		t.Fatal(err)
	}
	return si, sr
}

func TestSessionKeyScheduleAndRecordRoundTrip(t *testing.T) {
	si, sr := pairedSessions(t)
	var buf bytes.Buffer
	if err := si.WriteRecord(&buf, spec.TypeData, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("no record written")
	}
	typ, pt, err := sr.ReadRecord(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != spec.TypeData || !bytes.Equal(pt, []byte("payload")) {
		t.Fatalf("record = typ %d pt %q", typ, pt)
	}
	// Reverse direction uses the independent s2c key.
	buf.Reset()
	if err := sr.WriteRecord(&buf, spec.TypeData, []byte("reverse")); err != nil {
		t.Fatal(err)
	}
	_, pt, err = si.ReadRecord(&buf)
	if err != nil || !bytes.Equal(pt, []byte("reverse")) {
		t.Fatalf("reverse record pt %q err %v", pt, err)
	}
}

func TestSessionTamperWrongKeyWrongTranscriptAndReplay(t *testing.T) {
	seal := func(s *Session) []byte {
		var buf bytes.Buffer
		if err := s.WriteRecord(&buf, spec.TypeData, []byte("secret")); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	// Tampered ciphertext / auth tag is refused.
	si, sr := pairedSessions(t)
	frame := seal(si)
	frame[len(frame)-1] ^= 0xff
	if _, _, err := sr.ReadRecord(bytes.NewReader(frame)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	} else {
		wantFailureToken(t, err, spec.Replay)
	}

	// Wrong resource in AAD: a receiver derived for a different resource cannot open.
	hi, hr := pairedHandshakes(t)
	sender, err := hi.Derive("stream")
	if err != nil {
		t.Fatal(err)
	}
	wrongRes, err := hr.Derive("other-resource")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongRes.ReadRecord(bytes.NewReader(seal(sender))); err == nil {
		t.Fatal("record opened under wrong resource AAD")
	}

	// Wrong transcript hash: a receiver with a tampered th cannot open.
	hi, hr = pairedHandshakes(t)
	sender, _ = hi.Derive("stream")
	badTH := *hr
	badTH.TH[0] ^= 0xff
	wrongTH, err := badTH.Derive("stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongTH.ReadRecord(bytes.NewReader(seal(sender))); err == nil {
		t.Fatal("record opened under wrong transcript hash")
	}

	// Wrong session key (substituted ECDH) cannot open.
	hi, hr = pairedHandshakes(t)
	sender, _ = hi.Derive("stream")
	badKey := *hr
	badKey.ECDH = bytes.Repeat([]byte{1}, 32)
	wrongKey, err := badKey.Derive("stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongKey.ReadRecord(bytes.NewReader(seal(sender))); err == nil {
		t.Fatal("record opened under wrong session key")
	}
}

func TestSessionSequenceStrictness(t *testing.T) {
	si, sr := pairedSessions(t)
	var buf bytes.Buffer
	if err := si.WriteRecord(&buf, spec.TypeSessionReady, nil); err != nil {
		t.Fatal(err)
	}
	if err := si.WriteRecord(&buf, spec.TypeData, []byte("next")); err != nil {
		t.Fatal(err)
	}
	// Reading the first advances receiver seq to 1.
	if _, _, err := sr.ReadRecord(&buf); err != nil {
		t.Fatal(err)
	}
	// A duplicated frame (seq 0 again) is a replay.
	dup := bytes.Clone(buf.Bytes())
	// Re-read the legitimate seq=1 record first.
	if _, _, err := sr.ReadRecord(&buf); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sr.ReadRecord(bytes.NewReader(dup)); err == nil {
		t.Fatal("duplicate seq accepted")
	} else {
		wantFailureToken(t, err, spec.Replay)
	}
}

func TestSessionZeroizeClosesRecordIO(t *testing.T) {
	si, _ := pairedSessions(t)
	si.Zeroize()
	if err := si.WriteRecord(&bytes.Buffer{}, spec.TypeData, []byte("x")); err == nil {
		t.Fatal("write after zeroize succeeded")
	}
	if _, _, err := si.ReadRecord(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("read after zeroize succeeded")
	}
}
