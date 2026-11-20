// Package verify implements strict pairwise safety-number verification and
// pin storage. Pins are change-detection state only: they never authorize and
// never replace fresh proof of possession, a valid continuity chain, or a
// fresh per-session out-of-band confirmation (W5c, protocol-v1.md §6/§11).
// There is no degraded or TOFU input path in v1.
package verify

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/IFindMe/open-upp/identity"
)

const snChars = 52 // 32 bytes -> 52 unpadded base32 characters

// Digest returns the order-independent pairwise safety-number digest.
func Digest(fpA, fpB [32]byte) [32]byte {
	return identity.PairwiseSafetyDigest(fpA, fpB)
}

// Equal compares two full digests in constant time.
func Equal(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// Format renders a full digest in the required 7 groups (6x8 + final 4).
func Format(digest [32]byte) string {
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	var b strings.Builder
	for i := 0; i < len(s); i += 8 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 8
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// ParseSN strips ASCII spaces, uppercases, and decodes a 52-character
// pairwise safety number. Anything else (including a legacy 4-char code) is a
// usage error.
func ParseSN(s string) ([32]byte, error) {
	var digest [32]byte
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) != snChars {
		return digest, fmt.Errorf("-sn must be the %d-character pairwise safety number in 8-char groups", snChars)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(raw) != 32 {
		return digest, errors.New("-sn is not a valid base32 pairwise safety number")
	}
	copy(digest[:], raw)
	return digest, nil
}
