package noise

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// The Noise tokens appearing in Noise (pre)message patterns
// as in http://www.noiseprotocol.org/noise.html#handshake-pattern-basics
type NoiseTokens string

const (
	E   NoiseTokens = "e"
	S   NoiseTokens = "s"
	ES  NoiseTokens = "es"
	EE  NoiseTokens = "ee"
	SE  NoiseTokens = "se"
	SS  NoiseTokens = "ss"
	PSK NoiseTokens = "psk"
)

// The direction of a (pre)message pattern in canonical form (i.e. Alice-initiated form)
// as in http://www.noiseprotocol.org/noise.html#alice-and-bob
type MessageDirection string

const (
	Right MessageDirection = "->"
	Left  MessageDirection = "<-"
)

// The pre message pattern consisting of a message direction and some Noise tokens, if any.
// (if non empty, only tokens e and s are allowed: http://www.noiseprotocol.org/noise.html#handshake-pattern-basics)
type PreMessagePattern struct {
	direction MessageDirection
	tokens    []NoiseTokens
}

func NewPreMessagePattern(direction MessageDirection, tokens []NoiseTokens) PreMessagePattern {
	return PreMessagePattern{
		direction: direction,
		tokens:    tokens,
	}
}

func (p PreMessagePattern) Equals(b PreMessagePattern) bool {
	if p.direction != b.direction {
		return false
	}

	if len(p.tokens) != len(b.tokens) {
		return false
	}

	for i := range p.tokens {
		if p.tokens[i] != b.tokens[i] {
			return false
		}
	}

	return true
}

// The message pattern consisting of a message direction and some Noise tokens
// All Noise tokens are allowed
type MessagePattern struct {
	direction MessageDirection
	tokens    []NoiseTokens
}

func NewMessagePattern(direction MessageDirection, tokens []NoiseTokens) MessagePattern {
	return MessagePattern{
		direction: direction,
		tokens:    tokens,
	}
}

func (p MessagePattern) Equals(b MessagePattern) bool {
	if p.direction != b.direction {
		return false
	}

	if len(p.tokens) != len(b.tokens) {
		return false
	}

	for i := range p.tokens {
		if p.tokens[i] != b.tokens[i] {
			return false
		}
	}

	return true
}

// The handshake pattern object. It stores the handshake protocol name, the handshake pre message patterns and the handshake message patterns
type HandshakePattern struct {
	protocolID         byte
	name               string
	premessagePatterns []PreMessagePattern
	messagePatterns    []MessagePattern
	hashFn             func() hash.Hash
	cipherFn           func([]byte) (cipher.AEAD, error)
	tagSize            int
	dhKey              DHKey
}

func NewHandshakePattern(protocolID byte, name string, hashFn func() hash.Hash, cipherFn func([]byte) (cipher.AEAD, error), tagSize int, dhKey DHKey, preMessagePatterns []PreMessagePattern, messagePatterns []MessagePattern) HandshakePattern {
	return HandshakePattern{
		protocolID:         protocolID,
		name:               name,
		hashFn:             hashFn,
		cipherFn:           cipherFn,
		tagSize:            tagSize,
		dhKey:              dhKey,
		premessagePatterns: preMessagePatterns,
		messagePatterns:    messagePatterns,
	}
}

func (p HandshakePattern) Equals(b HandshakePattern) bool {

	if len(p.premessagePatterns) != len(b.premessagePatterns) {
		return false
	}

	for i := range p.premessagePatterns {
		if !p.premessagePatterns[i].Equals(b.premessagePatterns[i]) {
			return false
		}
	}

	if len(p.messagePatterns) != len(b.messagePatterns) {
		return false
	}

	for i := range p.messagePatterns {
		if !p.messagePatterns[i].Equals(b.messagePatterns[i]) {
			return false
		}
	}

	return p.name == b.name
}

var EmptyPreMessage = []PreMessagePattern{}

// Supported Noise handshake patterns as defined in https://rfc.vac.dev/spec/35/#specification

var K1K1 = NewHandshakePattern(
	Noise_K1K1_25519_ChaChaPoly_SHA256,
	"Noise_K1K1_25519_ChaChaPoly_SHA256",
	sha256.New,
	chacha20poly1305.New,
	16,
	DH25519,
	[]PreMessagePattern{
		NewPreMessagePattern(Right, []NoiseTokens{S}),
		NewPreMessagePattern(Left, []NoiseTokens{S}),
	},
	[]MessagePattern{
		NewMessagePattern(Right, []NoiseTokens{E}),
		NewMessagePattern(Left, []NoiseTokens{E, EE, ES}),
		NewMessagePattern(Right, []NoiseTokens{SE}),
	},
)

var XK1 = NewHandshakePattern(
	Noise_XK1_25519_ChaChaPoly_SHA256,
	"Noise_XK1_25519_ChaChaPoly_SHA256",
	sha256.New,
	chacha20poly1305.New,
	16,
	DH25519,
	[]PreMessagePattern{
		NewPreMessagePattern(Left, []NoiseTokens{S}),
	},
	[]MessagePattern{
		NewMessagePattern(Right, []NoiseTokens{E}),
		NewMessagePattern(Left, []NoiseTokens{E, EE, ES}),
		NewMessagePattern(Right, []NoiseTokens{S, SE}),
	},
)

var XX = NewHandshakePattern(
	Noise_XX_25519_ChaChaPoly_SHA256,
	"Noise_XX_25519_ChaChaPoly_SHA256",
	sha256.New,
	chacha20poly1305.New,
	16,
	DH25519,
	EmptyPreMessage,
	[]MessagePattern{
		NewMessagePattern(Right, []NoiseTokens{E}),
		NewMessagePattern(Left, []NoiseTokens{E, EE, S, ES}),
		NewMessagePattern(Right, []NoiseTokens{S, SE}),
	},
)

var XXpsk0 = NewHandshakePattern(
	Noise_XXpsk0_25519_ChaChaPoly_SHA256,
	"Noise_XXpsk0_25519_ChaChaPoly_SHA256",
	sha256.New,
	chacha20poly1305.New,
	16,
	DH25519,
	EmptyPreMessage,
	[]MessagePattern{
		NewMessagePattern(Right, []NoiseTokens{PSK, E}),
		NewMessagePattern(Left, []NoiseTokens{E, EE, S, ES}),
		NewMessagePattern(Right, []NoiseTokens{S, SE}),
	},
)

var WakuPairing = NewHandshakePattern(
	Noise_WakuPairing_25519_ChaChaPoly_SHA256,
	"Noise_WakuPairing_25519_ChaChaPoly_SHA256",
	sha256.New,
	chacha20poly1305.New,
	16,
	DH25519,
	[]PreMessagePattern{
		NewPreMessagePattern(Left, []NoiseTokens{E}),
	},
	[]MessagePattern{
		NewMessagePattern(Right, []NoiseTokens{E, EE}),
		NewMessagePattern(Left, []NoiseTokens{S, ES}),
		NewMessagePattern(Right, []NoiseTokens{S, SE, SS}),
	},
)

// Supported Protocol ID for PayloadV2 objects
// Protocol IDs are defined according to https://rfc.vac.dev/spec/35/#specification
const Noise_K1K1_25519_ChaChaPoly_SHA256 = 10
const Noise_XK1_25519_ChaChaPoly_SHA256 = 11
const Noise_XX_25519_ChaChaPoly_SHA256 = 12
const Noise_XXpsk0_25519_ChaChaPoly_SHA256 = 13
const Noise_WakuPairing_25519_ChaChaPoly_SHA256 = 14
const ChaChaPoly = 30
const None = 0

func IsProtocolIDSupported(protocolID byte) bool {
	return protocolID == Noise_K1K1_25519_ChaChaPoly_SHA256 ||
		protocolID == Noise_XK1_25519_ChaChaPoly_SHA256 ||
		protocolID == Noise_XX_25519_ChaChaPoly_SHA256 ||
		protocolID == Noise_XXpsk0_25519_ChaChaPoly_SHA256 ||
		protocolID == ChaChaPoly ||
		protocolID == Noise_WakuPairing_25519_ChaChaPoly_SHA256 ||
		protocolID == None
}

func GetHandshakePattern(protocol byte) (HandshakePattern, error) {
	switch protocol {
	case Noise_K1K1_25519_ChaChaPoly_SHA256:
		return K1K1, nil
	case Noise_XK1_25519_ChaChaPoly_SHA256:
		return XK1, nil
	case Noise_XX_25519_ChaChaPoly_SHA256:
		return XX, nil
	case Noise_XXpsk0_25519_ChaChaPoly_SHA256:
		return XXpsk0, nil
	case Noise_WakuPairing_25519_ChaChaPoly_SHA256:
		return WakuPairing, nil
	default:
		return HandshakePattern{}, errors.New("unsupported handshake pattern")
	}
}

// NewHandshake_XX_25519_ChaChaPoly_SHA256 creates a handshake where the initiator and responder are not aware of each other static keys
func NewHandshake_XX_25519_ChaChaPoly_SHA256(staticKeypair Keypair, initiator bool, prologue []byte) (*Handshake, error) {
	return NewHandshake(XX, staticKeypair, Keypair{}, prologue, nil, nil, initiator)
}

// NewHandshake_XXpsk0_25519_ChaChaPoly_SHA256 creates a handshake where the initiator and responder are not aware of each other static keys
// and use a preshared secret to strengthen their mutual authentication
func NewHandshake_XXpsk0_25519_ChaChaPoly_SHA256(staticKeypair Keypair, initiator bool, presharedKey []byte, prologue []byte) (*Handshake, error) {
	return NewHandshake(XXpsk0, staticKeypair, Keypair{}, prologue, presharedKey, nil, initiator)
}

// NewHandshake_K1K1_25519_ChaChaPoly_SHA256 creates a handshake where both initiator and recever know each other handshake. Only ephemeral keys
// are exchanged. This handshake is useful in case the initiator needs to instantiate a new separate encrypted communication
// channel with the responder
func NewHandshake_K1K1_25519_ChaChaPoly_SHA256(myStaticKeypair Keypair, initiator bool, peerStaticKey []byte, prologue []byte) (*Handshake, error) {
	var presharedKeys []*NoisePublicKey
	if initiator {
		presharedKeys = append(presharedKeys, byteToNoisePublicKey(K1K1.dhKey, myStaticKeypair.Public))
		presharedKeys = append(presharedKeys, byteToNoisePublicKey(K1K1.dhKey, peerStaticKey))
	} else {
		presharedKeys = append(presharedKeys, byteToNoisePublicKey(K1K1.dhKey, peerStaticKey))
		presharedKeys = append(presharedKeys, byteToNoisePublicKey(K1K1.dhKey, myStaticKeypair.Public))
	}
	return NewHandshake(K1K1, myStaticKeypair, Keypair{}, prologue, nil, presharedKeys, initiator)
}

// NewHandshake_XK1_25519_ChaChaPoly_SHA256 creates a handshake where the initiator knows the responder public static key. Within this handshake,
// the initiator and responder reciprocally authenticate their static keys using ephemeral keys. We note that while the responder's
// static key is assumed to be known to Alice (and hence is not transmitted), The initiator static key is sent to the
// responder encrypted with a key derived from both parties ephemeral keys and the responder's static key.
func NewHandshake_XK1_25519_ChaChaPoly_SHA256(myStaticKeypair Keypair, initiator bool, responderStaticKey []byte, prologue []byte) (*Handshake, error) {
	if !initiator {
		// Overwrite responderStaticKey with responder's static key in case they're different
		responderStaticKey = myStaticKeypair.Public
	}
	pubK := byteToNoisePublicKey(XK1.dhKey, responderStaticKey)
	return NewHandshake(XK1, myStaticKeypair, Keypair{}, prologue, nil, []*NoisePublicKey{pubK}, initiator)
}

// NewHandshake_WakuPairing_25519_ChaChaPoly_SHA256
func NewHandshake_WakuPairing_25519_ChaChaPoly_SHA256(myStaticKeypair Keypair, myEphemeralKeypair Keypair, initiator bool, prologue []byte, receiverEphemeralKey []byte) (*Handshake, error) {
	if !initiator {
		// Overwrite responderStaticKey with responder's static key in case they're different
		receiverEphemeralKey = myEphemeralKeypair.Public
	}
	pubK := byteToNoisePublicKey(WakuPairing.dhKey, receiverEphemeralKey)
	return NewHandshake(WakuPairing, myStaticKeypair, myEphemeralKeypair, prologue, nil, []*NoisePublicKey{pubK}, initiator)
}
