package noise

import (
	"bytes"
	"errors"
	"strings"
)

// The padding blocksize of  a transport message
const NoisePaddingBlockSize = 248

// The Handshake State as in https://noiseprotocol.org/noise.html#the-handshakestate-object
// Contains
//   - the local and remote ephemeral/static keys e,s,re,rs (if any)
//   - the initiator flag (true if the user creating the state is the handshake initiator, false otherwise)
//   - the handshakePattern (containing the handshake protocol name, and (pre)message patterns)
// This object is further extended from specifications by storing:
//   - a message pattern index msgPatternIdx indicating the next handshake message pattern to process
//   - the user's preshared psk, if any
type HandshakeState struct {
	s                Keypair
	e                Keypair
	rs               []byte
	re               []byte
	ss               *SymmetricState
	initiator        bool
	handshakePattern HandshakePattern
	msgPatternIdx    int
	psk              []byte
}

func NewHandshakeState(hsPattern HandshakePattern, psk []byte) *HandshakeState {
	return &HandshakeState{
		// By default the Handshake State initiator flag is set to false
		// Will be set to true when the user associated to the handshake state starts an handshake
		initiator:        false,
		handshakePattern: hsPattern,
		psk:              psk,
		ss:               NewSymmetricState(hsPattern),
		msgPatternIdx:    0,
	}
}

func (h *HandshakeState) Equals(b HandshakeState) bool {
	if !bytes.Equal(h.s.Private, b.s.Private) {
		return false
	}
	if !bytes.Equal(h.s.Public, b.s.Public) {
		return false
	}
	if !bytes.Equal(h.e.Private, b.e.Private) {
		return false
	}
	if !bytes.Equal(h.e.Public, b.e.Public) {
		return false
	}

	if !bytes.Equal(h.rs, b.rs) {
		return false
	}

	if !bytes.Equal(h.re, b.re) {
		return false
	}

	if !h.ss.Equals(b.ss) {
		return false
	}

	if h.initiator != b.initiator {
		return false
	}

	if !h.handshakePattern.Equals(b.handshakePattern) {
		return false
	}

	if h.msgPatternIdx != b.msgPatternIdx {
		return false
	}

	if !bytes.Equal(h.psk, b.psk) {
		return false
	}

	return true
}

func (h *HandshakeState) genMessageNametagSecrets() (nms1 []byte, nms2 []byte) {
	keyLen := h.handshakePattern.hashFn().Size()
	output := getHKDF(h.handshakePattern.hashFn, h.ss.h, []byte{}, keyLen*2)
	nms1 = output[:keyLen]
	nms2 = output[keyLen:]
	return
}

// Uses the cryptographic information stored in the input handshake state to generate a random message nametag
// In current implementation the messageNametag = HKDF(handshake hash value), but other derivation mechanisms can be implemented
func (h *HandshakeState) MessageNametag() MessageNametag {
	output := getHKDF(h.handshakePattern.hashFn, h.ss.h, []byte{}, MessageNametagLength)
	return BytesToMessageNametag(output)
}

// Handshake Processing

// Based on the message handshake direction and if the user is or not the initiator, returns a boolean tuple telling if the user
// has to read or write the next handshake message
func (h *HandshakeState) getReadingWritingState(direction MessageDirection) (reading bool, writing bool) {
	if h.initiator && direction == Right {
		// I'm Alice and direction is ->
		writing = true
	} else if h.initiator && direction == Left {
		// I'm Alice and direction is <-
		reading = true
	} else if !h.initiator && direction == Right {
		// I'm Bob and direction is ->
		reading = true
	} else if !h.initiator && direction == Left {
		// I'm Bob and direction is <-
		writing = true
	}
	return reading, writing
}

// Checks if a pre-message is valid according to Noise specifications
// http://www.noiseprotocol.org/noise.html#handshake-patterns
func (h *HandshakeState) isValid(msg []PreMessagePattern) bool {
	// Non-empty pre-messages can only have patterns "e", "s", "e,s" in each direction
	allowedPatterns := []PreMessagePattern{
		NewPreMessagePattern(Right, []NoiseTokens{S}),
		NewPreMessagePattern(Right, []NoiseTokens{E}),
		NewPreMessagePattern(Right, []NoiseTokens{E, S}),
		NewPreMessagePattern(Left, []NoiseTokens{S}),
		NewPreMessagePattern(Left, []NoiseTokens{E}),
		NewPreMessagePattern(Left, []NoiseTokens{E, S}),
	}

	// We check if pre message patterns are allowed
	for _, p := range msg {
		found := false
		for _, allowed := range allowedPatterns {
			if allowed.Equals(p) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// Handshake messages processing procedures

// Processes pre-message patterns
func (h *HandshakeState) processPreMessagePatternTokens(inPreMessagePKs []*NoisePublicKey) error {
	// I make a copy of the input pre-message public keys, so that I can easily delete processed ones without using iterators/counters
	preMessagePKs := append([]*NoisePublicKey(nil), inPreMessagePKs...)

	// Here we store currently processed pre message public key
	var currPK *NoisePublicKey

	// We retrieve the pre-message patterns to process, if any
	// If none, there's nothing to do
	if len(h.handshakePattern.premessagePatterns) == 0 {
		return nil
	}

	// If not empty, we check that pre-message is valid according to Noise specifications
	if !h.isValid(h.handshakePattern.premessagePatterns) {
		return errors.New("invalid pre-message in handshake")
	}

	// We iterate over each pattern contained in the pre-message
	for _, messagePattern := range h.handshakePattern.premessagePatterns {
		direction := messagePattern.direction
		tokens := messagePattern.tokens

		// We get if the user is reading or writing the current pre-message pattern
		reading, writing := h.getReadingWritingState(direction)

		// We process each message pattern token
		for _, token := range tokens {
			// We process the pattern token
			switch token {
			case E:
				// We expect an ephemeral key, so we attempt to read it (next PK to process will always be at index 0 of preMessagePKs)
				if len(preMessagePKs) > 0 {
					currPK = preMessagePKs[0]
				} else {
					return errors.New("noise pre-message read e, expected a public key")
				}

				// If user is reading the "e" token
				if reading {
					// We check if current key is encrypted or not. We assume pre-message public keys are all unencrypted on users' end
					if currPK.Flag == 0 {
						// Sets re and calls MixHash(re.public_key).
						h.re = currPK.Public
						h.ss.mixHash(h.re)
					} else {
						return errors.New("noise read e, incorrect encryption flag for pre-message public key")
					}
					// If user is writing the "e" token
				} else if writing {
					// When writing, the user is sending a public key,
					// We check that the public part corresponds to the set local key and we call MixHash(e.public_key).
					if bytes.Equal(h.e.Public, currPK.Public) {
						h.ss.mixHash(h.e.Public)
					} else {
						return errors.New("noise pre-message e key doesn't correspond to locally set e key pair")
					}
				}

				// Noise specification: section 9.2
				// In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
				// in a call to MixHash(e.public_key).
				// In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
				if strings.Contains(h.handshakePattern.name, string(PSK)) {
					h.ss.mixKey(currPK.Public)
				}

				// We delete processed public key
				preMessagePKs = preMessagePKs[1:]
			case S:
				// We expect a static key, so we attempt to read it (next PK to process will always be at index of preMessagePKs)
				if len(preMessagePKs) > 0 {
					currPK = preMessagePKs[0]
				} else {
					return errors.New("noise pre-message read s, expected a public key")
				}

				// If user is reading the "s" token
				if reading {
					// We check if current key is encrypted or not. We assume pre-message public keys are all unencrypted on users' end
					if currPK.Flag == 0 {
						// Sets rs and calls MixHash(rs.public_key).
						h.rs = currPK.Public
						h.ss.mixHash(h.rs)
					} else {
						return errors.New("noise read s, incorrect encryption flag for pre-message public key")
					}

					// If user is writing the "s" token
				} else if writing {
					// If writing, it means that the user is sending a public key,
					// We check that the public part corresponds to the set local key and we call MixHash(s.public_key).
					if bytes.Equal(h.s.Public, currPK.Public) {
						h.ss.mixHash(h.s.Public)
					} else {
						return errors.New("noise pre-message s key doesn't correspond to locally set s key pair")
					}
				}

				// Noise specification: section 9.2
				// In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
				// in a call to MixHash(e.public_key).
				// In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
				if strings.Contains(h.handshakePattern.name, string(PSK)) {
					h.ss.mixKey(currPK.Public)
				}

				// We delete processed public key
				preMessagePKs = preMessagePKs[1:]
			default:
				return errors.New("invalid Token for pre-message pattern")
			}
		}
	}
	return nil
}

// This procedure encrypts/decrypts the implicit payload attached at the end of every message pattern
// An optional extraAd to pass extra additional data in encryption/decryption can be set (useful to authenticate messageNametag)
func (h *HandshakeState) processMessagePatternPayload(transportMessage []byte, extraAd []byte) ([]byte, error) {
	var payload []byte
	var err error

	// We retrieve current message pattern (direction + tokens) to process
	direction := h.handshakePattern.messagePatterns[h.msgPatternIdx].direction

	// We get if the user is reading or writing the input handshake message
	reading, writing := h.getReadingWritingState(direction)

	// We decrypt the transportMessage, if any
	if reading {
		payload, err = h.ss.decryptAndHash(transportMessage, extraAd)
		if err != nil {
			return nil, err
		}
		payload, err = PKCS7_Unpad(payload, NoisePaddingBlockSize)
		if err != nil {
			return nil, err
		}
	} else if writing {
		payload, err = PKCS7_Pad(transportMessage, NoisePaddingBlockSize)
		if err != nil {
			return nil, err
		}
		payload, err = h.ss.encryptAndHash(payload, extraAd)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("undefined state")
	}
	return payload, nil
}

// We process an input handshake message according to current handshake state and we return the next handshake step's handshake message
func (h *HandshakeState) processMessagePatternTokens(inputHandshakeMessage []*NoisePublicKey) ([]*NoisePublicKey, error) {
	// We retrieve current message pattern (direction + tokens) to process
	messagePattern := h.handshakePattern.messagePatterns[h.msgPatternIdx]
	direction := messagePattern.direction
	tokens := messagePattern.tokens

	// We get if the user is reading or writing the input handshake message
	reading, writing := h.getReadingWritingState(direction)

	// I make a copy of the handshake message so that I can easily delete processed PKs without using iterators/counters
	// (Possibly) non-empty if reading
	inHandshakeMessage := append([]*NoisePublicKey(nil), inputHandshakeMessage...)

	// The party's output public keys
	// (Possibly) non-empty if writing
	var outHandshakeMessage []*NoisePublicKey

	// In currPK we store the currently processed public key from the handshake message
	var currPK *NoisePublicKey

	// We process each message pattern token
	for _, token := range tokens {
		switch token {
		case E:
			// If user is reading the "s" token
			if reading {
				// We expect an ephemeral key, so we attempt to read it (next PK to process will always be at index 0 of preMessagePKs)
				if len(inHandshakeMessage) > 0 {
					currPK = inHandshakeMessage[0]
				} else {
					return nil, errors.New("noise read e, expected a public key")
				}

				// We check if current key is encrypted or not
				// Note: by specification, ephemeral keys should always be unencrypted. But we support encrypted ones.
				if currPK.Flag == 0 {
					// Unencrypted Public Key
					// Sets re and calls MixHash(re.public_key).
					h.re = currPK.Public
					h.ss.mixHash(h.re)

					// The following is out of specification: we call decryptAndHash for encrypted ephemeral keys, similarly as happens for (encrypted) static keys
				} else if currPK.Flag == 1 {
					// Encrypted public key
					// Decrypts re, sets re and calls MixHash(re.public_key).
					decRe, err := h.ss.decryptAndHash(currPK.Public, nil)
					if err != nil {
						return nil, err
					}
					h.re = decRe
				} else {
					return nil, errors.New("noise read e, incorrect encryption flag for public key")
				}

				// Noise specification: section 9.2
				// In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
				// in a call to MixHash(e.public_key).
				// In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
				if strings.Contains(h.handshakePattern.name, string(PSK)) {
					h.ss.mixKey(h.re)
				}

				// We delete processed public key
				inHandshakeMessage = inHandshakeMessage[1:]

				// If user is writing the "e" token
			} else if writing {
				// We generate a new ephemeral keypair
				e, err := DH25519.GenerateKeypair()
				if err != nil {
					return nil, err
				}
				h.e = e

				// We update the state
				h.ss.mixHash(h.e.Public)

				// Noise specification: section 9.2
				// In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
				// in a call to MixHash(e.public_key).
				// In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
				if strings.Contains(h.handshakePattern.name, string(PSK)) {
					h.ss.mixKey(h.e.Public)
				}

				// We add the ephemeral public key to the Waku payload
				outHandshakeMessage = append(outHandshakeMessage, byteToNoisePublicKey(h.handshakePattern.dhKey, h.e.Public))
			}
		case S:
			// If user is reading the "s" token
			if reading {
				// We expect a static key, so we attempt to read it (next PK to process will always be at index 0 of preMessagePKs)
				if len(inHandshakeMessage) > 0 {
					currPK = inHandshakeMessage[0]
				} else {
					return nil, errors.New("noise read s, expected a public key")
				}

				// We check if current key is encrypted or not
				if currPK.Flag == 0 {
					// Unencrypted Public Key
					// Sets re and calls MixHash(re.public_key).
					h.rs = currPK.Public
					h.ss.mixHash(h.rs)
				} else if currPK.Flag == 1 {
					// Encrypted public key
					// Decrypts rs, sets rs and calls MixHash(rs.public_key).
					decRS, err := h.ss.decryptAndHash(currPK.Public, nil)
					if err != nil {
						return nil, err
					}
					h.rs = decRS
				} else {
					return nil, errors.New("noise read s, incorrect encryption flag for public key")
				}

				// We delete processed public key
				inHandshakeMessage = inHandshakeMessage[1:]

				// If user is writing the "s" token
			} else if writing {
				// If the local static key is not set (the handshake state was not properly initialized), we raise an error
				if h.s.IsDefault() {
					return nil, errors.New("static key not set")
				}

				// We encrypt the public part of the static key in case a key is set in the Cipher State
				// That is, encS may either be an encrypted or unencrypted static key.
				encS, err := h.ss.encryptAndHash(h.s.Public, nil)
				if err != nil {
					return nil, err
				}
				// We add the (encrypted) static public key to the Waku payload
				// Note that encS = (Enc(s) || tag) if encryption key is set, otherwise encS = s.
				// We distinguish these two cases by checking length of encryption and we set the proper encryption flag
				if len(encS) > h.handshakePattern.dhKey.DHLen() {
					outHandshakeMessage = append(outHandshakeMessage, byteToNoisePublicKey(h.handshakePattern.dhKey, encS))
				} else {
					outHandshakeMessage = append(outHandshakeMessage, byteToNoisePublicKey(h.handshakePattern.dhKey, encS))
				}
			}
		case PSK:
			// If user is reading the "psk" token

			// Calls MixKeyAndHash(psk)
			h.ss.mixKeyAndHash(h.psk)
		case EE:
			// If user is reading the "ee" token

			// If local and/or remote ephemeral keys are not set, we raise an error
			if h.e.IsDefault() || len(h.re) == 0 {
				return nil, errors.New("local or remote ephemeral key not set")
			}

			// Calls MixKey(DH(e, re)).
			k, err := h.handshakePattern.dhKey.DH(h.e.Private, h.re)
			if err != nil {
				return nil, err
			}
			h.ss.mixKey(k)
		case ES:
			// If user is reading the "es" token

			// We check if keys are correctly set.
			// If both present, we call MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
			if h.initiator {
				if h.e.IsDefault() || len(h.rs) == 0 {
					return nil, errors.New("local or remote ephemeral/static key not set")
				}

				k, err := h.handshakePattern.dhKey.DH(h.e.Private, h.rs)
				if err != nil {
					return nil, err
				}
				h.ss.mixKey(k)
			} else {
				if len(h.re) == 0 || h.s.IsDefault() {
					return nil, errors.New("local or remote ephemeral/static key not set")
				}

				k, err := h.handshakePattern.dhKey.DH(h.s.Private, h.re)
				if err != nil {
					return nil, err
				}
				h.ss.mixKey(k)
			}
		case SE:
			// If user is reading the "se" token

			// We check if keys are correctly set.
			// If both present, call MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
			if h.initiator {
				if h.s.IsDefault() || len(h.re) == 0 {
					return nil, errors.New("local or remote ephemeral/static key not set")
				}

				k, err := h.handshakePattern.dhKey.DH(h.s.Private, h.re)
				if err != nil {
					return nil, err
				}
				h.ss.mixKey(k)
			} else {
				if len(h.rs) == 0 || h.e.IsDefault() {
					return nil, errors.New("local or remote ephemeral/static key not set")
				}

				k, err := h.handshakePattern.dhKey.DH(h.e.Private, h.rs)
				if err != nil {
					return nil, err
				}
				h.ss.mixKey(k)
			}
		case SS:
			// If user is reading the "ss" token

			// If local and/or remote static keys are not set, we raise an error
			if h.s.IsDefault() || len(h.rs) == 0 {
				return nil, errors.New("local or remote static key not set")
			}

			// Calls MixKey(DH(s, rs)).
			k, err := h.handshakePattern.dhKey.DH(h.s.Private, h.rs)
			if err != nil {
				return nil, err
			}
			h.ss.mixKey(k)
		}
	}

	return outHandshakeMessage, nil
}
