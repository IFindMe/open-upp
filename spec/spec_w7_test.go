package spec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// TestCanonGoldenAndDeterministic pins the exact CANON-1 byte layout:
// u32_be len || bytes per field. This is a W7 golden vector (W3 D1 / W7-AC4).
func TestCanonGoldenAndDeterministic(t *testing.T) {
	got := Canon([]byte("ab"), []byte("c"))
	want, _ := hex.DecodeString("0000000261620000000163")
	if !bytes.Equal(got, want) {
		t.Fatalf("Canon = %x, want golden %x", got, want)
	}
	for i := 0; i < 5; i++ {
		if again := Canon([]byte("ab"), []byte("c")); !bytes.Equal(again, got) {
			t.Fatal("CANON-1 is not deterministic")
		}
	}
	// Empty field is an encoded zero-length field, never an omitted field.
	empty := Canon(nil)
	if !bytes.Equal(empty, []byte{0, 0, 0, 0}) {
		t.Fatalf("Canon(empty) = %x, want 00000000", empty)
	}
}

func TestCanonIntegerWidths(t *testing.T) {
	if !bytes.Equal(U8(Version), []byte{1}) {
		t.Fatal("U8 width/value wrong")
	}
	if !bytes.Equal(U32(0x00010203), []byte{0, 1, 2, 3}) {
		t.Fatal("U32 must be 4-byte big-endian")
	}
	if !bytes.Equal(U64(0x0000000102030405), []byte{0, 0, 0, 1, 2, 3, 4, 5}) {
		t.Fatal("U64 must be 8-byte big-endian")
	}
}

func TestDecodeFieldsRoundTripAndMalformed(t *testing.T) {
	blob := Canon([]byte("one"), []byte(""), []byte("three"))
	f := DecodeFields(blob)
	if got := string(f.Next()); got != "one" {
		t.Fatalf("field0 = %q", got)
	}
	if got := f.Next(); len(got) != 0 {
		t.Fatalf("field1 = %q, want empty", got)
	}
	if got := string(f.Next()); got != "three" {
		t.Fatalf("field2 = %q", got)
	}
	if err := f.Done(); err != nil {
		t.Fatalf("Done on valid blob: %v", err)
	}

	// Trailing bytes must be rejected.
	f = DecodeFields(append(append([]byte{}, blob...), 0x00))
	f.Next()
	f.Next()
	f.Next()
	if err := f.Done(); err == nil {
		t.Fatal("trailing CANON bytes accepted")
	}

	// Truncated length prefix, truncated body, and unterminated field all fail.
	bad := [][]byte{
		{0, 0},                        // short length prefix
		{0, 0, 0, 5, 'a'},             // body shorter than declared length
		{0, 0, 0, 1, 'a', 0, 0, 0, 2}, // second field declares missing body
	}
	for i, b := range bad {
		f := DecodeFields(b)
		_ = f.Next()
		_ = f.Next()
		if err := f.Done(); err == nil {
			t.Fatalf("malformed blob %d accepted", i)
		}
	}
	// Once a decoder fails, every subsequent Next stays failed.
	f = DecodeFields([]byte{0, 0})
	if got := f.Next(); len(got) != 0 {
		t.Fatal("Next on failed decoder returned data")
	}
}

func TestFrameBoundaries(t *testing.T) {
	payload := append([]byte{TypeHello}, Canon([]byte("x"))...)
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[:4], U32(uint32(len(payload)))) {
		t.Fatal("frame length prefix not u32_be payload length")
	}
	decoded, err := DecodeFrame(bytes.NewReader(frame))
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("frame round trip = %x, err %v", decoded, err)
	}

	// Oversize rejected before allocation on both encode and decode.
	big := bytes.Repeat([]byte{0}, MaxFrame+1)
	if _, err := EncodeFrame(big); err == nil {
		t.Fatal("EncodeFrame accepted oversize payload")
	}
	fakeHdr := append(U32(uint32(MaxFrame+1)), 0x00)
	if _, err := DecodeFrame(bytes.NewReader(fakeHdr)); err == nil {
		t.Fatal("DecodeFrame accepted oversize length")
	}
	// Exact bound is allowed.
	atBound := bytes.Repeat([]byte{0}, MaxFrame)
	if _, err := EncodeFrame(atBound); err != nil {
		t.Fatalf("EncodeFrame rejected exact bound: %v", err)
	}

	// Truncated header and truncated body both error.
	for _, b := range [][]byte{{0, 0}, {0, 0, 0, 4, 1, 2}} {
		if _, err := DecodeFrame(bytes.NewReader(b)); !errors.Is(err, io.ErrUnexpectedEOF) && err == nil {
			t.Fatalf("truncated frame accepted: %x", b)
		}
	}
}

// TestHKDFRFC5869 pins HKDF-SHA256 against RFC 5869 test case 1.
func TestHKDFRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22) // RFC 5869 test case 1
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	prk, _ := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	okm, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	if got := HKDFExtract(salt, ikm); !bytes.Equal(got, prk) {
		t.Fatalf("HKDFExtract = %x, want %x", got, prk)
	}
	got, err := HKDFExpand(prk, info, len(okm))
	if err != nil || !bytes.Equal(got, okm) {
		t.Fatalf("HKDFExpand = %x, err %v, want %x", got, err, okm)
	}
	got2, err := HKDF(salt, ikm, info, len(okm))
	if err != nil || !bytes.Equal(got2, okm) {
		t.Fatalf("HKDF = %x, err %v", got2, err)
	}
	if _, err := HKDFExpand(prk, info, 255*32+1); err == nil {
		t.Fatal("HKDFExpand accepted out-of-range length")
	}
}
