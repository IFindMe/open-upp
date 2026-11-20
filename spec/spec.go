// Package spec owns the frozen protocol-v1 constants: domain tags, suite/version
// registry, bounds, frame types and stable reason tokens. It has no dependency
// on any other open-upp package and is the only place a domain-tag literal may
// appear (W3 D1; docs/architecture/protocol-v1.md §2).
package spec

// Version and suite registry (W3 D2). Only this exact set is accepted; there is
// no fallback and no extension bit.
const (
	Version  uint8  = 1
	SuiteSet string = "Ed25519,X25519,AES-256-GCM"
	Suite    string = "Ed25519,X25519,AES-256-GCM"
	SuiteID  string = "Ed25519"
	KEXID    string = "X25519"
	AEADID   string = "AES-256-GCM"
	KDFID    string = "HKDF-SHA256"
	HashID   string = "SHA-256"
)

// Domain-tag registry (W3 D1). The first six values are copied verbatim from
// identity/identity.go and preserve existing fingerprint/signature bytes.
const (
	TagFingerprint       = "open-upp/identity/fingerprint/v1"
	TagKeyFingerprint    = "open-upp/identity/key-fingerprint/v1"
	TagSelfBinding       = "open-upp/identity/self-bind/v1"
	TagContinuity        = "open-upp/identity/continuity/v1"
	TagAcknowledgment    = "open-upp/identity/acknowledgment/v1"
	TagProofOfPossession = "open-upp/identity/pop/v1"
	TagSafetyNumber      = "open-upp/identity/safety-number/v1"
	TagHandshakePoP      = "open-upp/handshake/pop/v1"
	TagSessionKDF        = "open-upp/session/kdf/v1"
	TagSessionData       = "open-upp/session/data/v1"
	TagGrant             = "open-upp/grant/v1"
)

// Frozen bounds (W3 D2; protocol-v1.md §2).
const (
	MaxKeyLog         = 16
	MaxFrame          = 65536
	FreshnessWindowS  = 60
	RetryBudget       = 3
	RouteTimeoutS     = 5
	HandshakeTimeoutS = 10
	MaxChallengeCache = 4096
	MaxGrants         = 1024
)

// Frame payload type bytes (protocol-v1.md §4).
const (
	TypeHello         byte = 0x01
	TypeHelloResponse byte = 0x02
	TypeFinished      byte = 0x03
	TypeSessionReady  byte = 0x04
	TypeData          byte = 0x05
	TypeClose         byte = 0x06
	TypeError         byte = 0x07
)

// Stable reason tokens shared by every terminal state (W3 D8, W4 §7a,
// protocol-v1.md §8). No other layer should invent a token.
const (
	RouteFailed         = "route_failed"
	UnknownPeer         = "unknown_peer"
	VersionRejected     = "version_rejected"
	BadProof            = "bad_proof"
	StaleChallenge      = "stale_challenge"
	UnverifiedSN        = "unverified_safety_number"
	VerificationAborted = "verification_aborted"
	AuthorizationDenied = "authorization_denied"
	Revoked             = "revoked"
	SessionKeyError     = "session_key_error"
	Replay              = "replay"
	ConnectionLost      = "connection_lost"
	ScopeViolation      = "scope_violation"
	Ended               = "ended"
	KeyRotated          = "key_rotated"
	Granted             = "granted"
	Verified            = "verified"
	Authorized          = "authorized"
	SessionOpen         = "session_open"
	Listening           = "listening"
	UsageError          = "usage error"
)

// Failure is a terminal or recoverable protocol failure carrying one of the
// stable tokens above plus a secret-free sentence and optional recovery line.
type Failure struct {
	Token   string
	Message string
	Next    string
	Exit    int
}

func (f *Failure) Error() string { return f.Token + ": " + f.Message }

// NewFailure builds a Failure. Exit defaults to 1 unless explicitly set.
func NewFailure(token, message, next string) *Failure {
	return &Failure{Token: token, Message: message, Next: next, Exit: 1}
}
