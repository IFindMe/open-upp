package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/IFindMe/open-upp/spec"
)

func failureToken(t *testing.T, err error) string {
	t.Helper()
	var f *spec.Failure
	if !errors.As(err, &f) {
		t.Fatalf("error %v is not a *spec.Failure", err)
	}
	return f.Token
}

func validHello() Hello {
	return Hello{
		Version:   spec.Version,
		SuiteSet:  spec.SuiteSet,
		Challenge: bytes.Repeat([]byte{1}, challengeSize),
		EPHPub:    bytes.Repeat([]byte{2}, ephPubSize),
		Record:    bytes.Repeat([]byte{3}, 32),
	}
}

func TestHelloBuildParseAndReject(t *testing.T) {
	h := validHello()
	payload, err := BuildHello(h)
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != spec.TypeHello {
		t.Fatal("HELLO type byte wrong")
	}
	parsed, raw, err := ParseHello(payload)
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatalf("ParseHello raw mismatch: err %v", err)
	}
	if !bytes.Equal(parsed.Challenge, h.Challenge) || !bytes.Equal(parsed.Record, h.Record) {
		t.Fatal("HELLO field round trip failed")
	}

	// Downgrade/unknown version and unknown suite must be version_rejected, never fallback.
	bad := h
	bad.Version = 0
	if _, err := BuildHello(bad); failureToken(t, err) != spec.VersionRejected {
		t.Fatal("version 0 HELLO accepted at build")
	}
	bad = validHello()
	bad.SuiteSet = "Ed25519,X25519"
	if _, err := BuildHello(bad); failureToken(t, err) != spec.VersionRejected {
		t.Fatal("unknown suite HELLO accepted at build")
	}
	// Tamper the decoded version byte to exercise ParseHello's registry check.
	tampered := bytes.Clone(payload)
	// version is the first CANON field body: type(1)+len(4) then the value.
	tampered[5] = 2
	if _, _, err := ParseHello(tampered); failureToken(t, err) != spec.VersionRejected {
		t.Fatal("downgraded HELLO not rejected on parse")
	}
	// Truncated payload rejected.
	if _, _, err := ParseHello(payload[:len(payload)-1]); err == nil {
		t.Fatal("truncated HELLO accepted")
	}
}

func TestHelloResponseTranscriptPrefixBinding(t *testing.T) {
	base := HelloResponse{
		Version:   spec.Version,
		Suite:     spec.Suite,
		Challenge: bytes.Repeat([]byte{4}, challengeSize),
		EPHPub:    bytes.Repeat([]byte{5}, ephPubSize),
		Record:    bytes.Repeat([]byte{6}, 32),
		Pop:       bytes.Repeat([]byte{7}, popSize),
	}
	payload, prefix, err := BuildHelloResponse(base)
	if err != nil {
		t.Fatal(err)
	}
	parsed, parsedPrefix, err := ParseHelloResponse(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prefix, parsedPrefix) {
		t.Fatal("build prefix != parse prefix: transcript bytes differ between peers")
	}
	if bytes.Contains(prefix, base.Pop) {
		t.Fatal("transcript prefix contains the PoP")
	}
	// Changing only the PoP must not change the transcript-bound prefix.
	other := base
	other.Pop = bytes.Repeat([]byte{9}, popSize)
	_, otherPrefix, err := BuildHelloResponse(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prefix, otherPrefix) {
		t.Fatal("transcript prefix changed when only PoP changed")
	}
	// Changing any transcript field must change the prefix.
	mutations := []HelloResponse{}
	m1 := base
	m1.Challenge = bytes.Repeat([]byte{8}, challengeSize)
	mutations = append(mutations, m1)
	m2 := base
	m2.EPHPub = bytes.Repeat([]byte{10}, ephPubSize)
	mutations = append(mutations, m2)
	m3 := base
	m3.Record = bytes.Repeat([]byte{11}, 48)
	mutations = append(mutations, m3)
	for i, m := range mutations {
		_, p, err := BuildHelloResponse(m)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(prefix, p) {
			t.Fatalf("transcript prefix unchanged for mutation %d", i)
		}
	}
	if !bytes.Equal(parsed.Pop, base.Pop) {
		t.Fatal("PoP field did not round trip")
	}
}

func TestHelloResponseRejectsBadVersionSuiteAndFields(t *testing.T) {
	base := HelloResponse{
		Version: spec.Version, Suite: spec.Suite,
		Challenge: bytes.Repeat([]byte{1}, challengeSize),
		EPHPub:    bytes.Repeat([]byte{2}, ephPubSize),
		Record:    bytes.Repeat([]byte{3}, 32),
		Pop:       bytes.Repeat([]byte{4}, popSize),
	}
	bad := base
	bad.Version = 0
	if _, _, err := BuildHelloResponse(bad); failureToken(t, err) != spec.VersionRejected {
		t.Fatal("version 0 HELLO_RESPONSE accepted")
	}
	bad = base
	bad.Suite = "Unknown"
	if _, _, err := BuildHelloResponse(bad); failureToken(t, err) != spec.VersionRejected {
		t.Fatal("unknown suite HELLO_RESPONSE accepted")
	}
	bad = base
	bad.Pop = bytes.Repeat([]byte{4}, popSize-1)
	if _, _, err := BuildHelloResponse(bad); err == nil {
		t.Fatal("short PoP accepted")
	}
	payload, _, _ := BuildHelloResponse(base)
	if _, _, err := ParseHelloResponse(payload[:len(payload)-1]); err == nil {
		t.Fatal("truncated HELLO_RESPONSE accepted")
	}
}

func TestFinishedSizeAndType(t *testing.T) {
	payload, err := BuildFinished(Finished{Pop: bytes.Repeat([]byte{1}, popSize)})
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != spec.TypeFinished {
		t.Fatal("FINISHED type byte wrong")
	}
	if _, err := ParseFinished(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildFinished(Finished{Pop: make([]byte, popSize-1)}); err == nil {
		t.Fatal("short FINISHED PoP accepted")
	}
	bad := bytes.Clone(payload)
	bad[0] = spec.TypeData
	if _, err := ParseFinished(bad); err == nil {
		t.Fatal("non-FINISHED type accepted as FINISHED")
	}
}
