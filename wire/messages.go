// Package wire implements the protocol-v1 handshake record schemas on top of
// the canonical CANON-1 encoding in spec (protocol-v1.md §4, W3 §3).
package wire

// Hello is the initiator's first cleartext message.
type Hello struct {
	Version   uint8
	SuiteSet  string
	Challenge []byte // 32 random bytes, issued by the sender
	EPHPub    []byte // 32-byte X25519 public key
	Record    []byte // CANON-1 encoded public identity record
}

// HelloResponse is the responder's cleartext message; Pop is signed last so
// the transcript hash can commit to everything before it.
type HelloResponse struct {
	Version   uint8
	Suite     string
	Challenge []byte // 32 random bytes, issued by the responder
	EPHPub    []byte
	Record    []byte
	Pop       []byte // 64-byte Ed25519 signature over the transcript-bound PoP blob
}

// Finished carries the initiator's proof of possession.
type Finished struct {
	Pop []byte
}
