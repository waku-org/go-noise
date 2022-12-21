package noise

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

// Noise state machine

var ErrUnexpectedMessageNametag = errors.New("the message nametag of the read message doesn't match the expected one")
var ErrHandshakeComplete = errors.New("handshake complete")

// While processing messages patterns, users either:
// - read (decrypt) the other party's (encrypted) transport message
// - write (encrypt) a message, sent through a PayloadV2
// These two intermediate results are stored in the HandshakeStepResult data structure

// HandshakeStepResult stores the intermediate result of processing messages patterns
type HandshakeStepResult struct {
	PayloadV2        *PayloadV2
	TransportMessage []byte
}

// When a handshake is complete, the HandshakeResult will contain the two
// Cipher States used to encrypt/decrypt outbound/inbound messages
// The recipient static key rs and handshake hash values h are stored to address some possible future applications (channel-binding, session management, etc.).
// However, are not required by Noise specifications and are thus optional
type HandshakeResult struct {
	csOutbound *CipherState
	csInbound  *CipherState

	// Optional fields:
	nametagsInbound  MessageNametagBuffer
	nametagsOutbound MessageNametagBuffer
	rs               []byte
	h                []byte
}

func NewHandshakeResult(csOutbound *CipherState, csInbound *CipherState) *HandshakeResult {
	return &HandshakeResult{
		csInbound:  csInbound,
		csOutbound: csOutbound,
	}
}

// Noise specification, Section 5:
// Transport messages are then encrypted and decrypted by calling EncryptWithAd()
// and DecryptWithAd() on the relevant CipherState with zero-length associated data.
// If DecryptWithAd() signals an error due to DECRYPT() failure, then the input message is discarded.
// The application may choose to delete the CipherState and terminate the session on such an error,
// or may continue to attempt communications. If EncryptWithAd() or DecryptWithAd() signal an error
// due to nonce exhaustion, then the application must delete the CipherState and terminate the session.

// Writes an encrypted message using the proper Cipher State
func (hr *HandshakeResult) WriteMessage(transportMessage []byte, outboundMessageNametagBuffer *MessageNametagBuffer) (*PayloadV2, error) {
	payload2 := &PayloadV2{}

	// We set the message nametag using the input buffer
	if outboundMessageNametagBuffer != nil {
		payload2.MessageNametag = outboundMessageNametagBuffer.Pop()
	} else {
		payload2.MessageNametag = hr.nametagsOutbound.Pop()
	}

	// According to 35/WAKU2-NOISE RFC, no Handshake protocol information is sent when exchanging messages
	// This correspond to setting protocol-id to 0
	payload2.ProtocolId = 0
	// We pad the transport message
	paddedTransportMessage, err := PKCS7_Pad(transportMessage, NoisePaddingBlockSize)
	if err != nil {
		return nil, err
	}

	// Encryption is done with zero-length associated data as per specification
	transportMessage, err = hr.csOutbound.encryptWithAd(payload2.MessageNametag[:], paddedTransportMessage)
	if err != nil {
		return nil, err
	}

	payload2.TransportMessage = transportMessage

	return payload2, nil
}

// Reads an encrypted message using the proper Cipher State
// Decryption is attempted only if the input PayloadV2 has a messageNametag equal to the one expected
func (hr *HandshakeResult) ReadMessage(readPayload2 *PayloadV2, inboundMessageNametagBuffer *MessageNametagBuffer) ([]byte, error) {
	// The output decrypted message
	var message []byte

	// If the message nametag does not correspond to the nametag expected in the inbound message nametag buffer
	// an error is raised (to be handled externally, i.e. re-request lost messages, discard, etc.)
	if inboundMessageNametagBuffer != nil {
		err := inboundMessageNametagBuffer.CheckNametag(readPayload2.MessageNametag)
		if err != nil {
			return nil, err
		}
	} else {
		err := hr.nametagsInbound.CheckNametag(readPayload2.MessageNametag)
		if err != nil {
			return nil, err
		}
	}

	// At this point the messageNametag matches the expected nametag.
	// According to 35/WAKU2-NOISE RFC, no Handshake protocol information is sent when exchanging messages
	if readPayload2.ProtocolId == 0 {
		// Decryption is done with messageNametag as associated data
		paddedMessage, err := hr.csInbound.decryptWithAd(readPayload2.MessageNametag[:], readPayload2.TransportMessage)
		if err != nil {
			return nil, err
		}

		// We unpad the decrypted message
		message, err = PKCS7_Unpad(paddedMessage, NoisePaddingBlockSize)
		if err != nil {
			return nil, err
		}

		// The message successfully decrypted, we can delete the first element of the inbound Message Nametag Buffer
		hr.nametagsInbound.Delete(1)
	}

	return message, nil
}

type Handshake struct {
	hs       *HandshakeState
	hsResult *HandshakeResult
}

func NewHandshake(hsPattern HandshakePattern, staticKey Keypair, ephemeralKey Keypair, prologue []byte, psk []byte, preMessagePKs []*NoisePublicKey, initiator bool) (*Handshake, error) {
	result := &Handshake{}
	result.hs = NewHandshakeState(hsPattern, psk)
	result.hs.ss.mixHash(prologue)
	result.hs.e = ephemeralKey
	result.hs.s = staticKey
	result.hs.psk = psk
	result.hs.msgPatternIdx = 0
	result.hs.initiator = initiator

	// We process any eventual handshake pre-message pattern by processing pre-message public keys
	err := result.hs.processPreMessagePatternTokens(preMessagePKs)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (h *Handshake) Equals(b *Handshake) bool {
	return h.hs.Equals(*b.hs)
}

// Uses the cryptographic information stored in the input handshake state to generate a random message nametag
// In current implementation the messageNametag = HKDF(handshake hash value), but other derivation mechanisms can be implemented
func (hs *Handshake) ToMessageNametag() (MessageNametag, error) {
	output := getHKDF(hs.hs.handshakePattern.hashFn, hs.hs.ss.h, nil, 16)
	return BytesToMessageNametag(output), nil
}

// Generates an 8 decimal digits authorization code using HKDF and the handshake state
func (h *Handshake) Authcode() (string, error) {
	output0 := getHKDF(h.hs.handshakePattern.hashFn, h.hs.ss.h, nil, 8)
	bn := new(big.Int)
	bn.SetBytes(output0)
	code := new(big.Int)
	code.Mod(bn, big.NewInt(100_000_000))
	return fmt.Sprintf("'%08s'", code.String()), nil
}

// Advances 1 step in handshake
//  Each user in a handshake alternates writing and reading of handshake messages.
// If the user is writing the handshake message, the transport message (if not empty) and eventually a non-empty message nametag has to be passed to transportMessage and messageNametag and readPayloadV2 can be left to its default value
// It the user is reading the handshake message, the read payload v2 has to be passed to readPayloadV2 and the transportMessage can be left to its default values. Decryption is skipped if the PayloadV2 read doesn't have a message nametag equal to messageNametag (empty input nametags are converted to all-0 MessageNametagLength bytes arrays)
func (h *Handshake) Step(readPayloadV2 *PayloadV2, transportMessage []byte, messageNametag MessageNametag) (*HandshakeStepResult, error) {
	hsStepResult := &HandshakeStepResult{}

	if h.IsComplete() {
		return nil, ErrHandshakeComplete
	}

	// We process the next handshake message pattern

	// We get if the user is reading or writing the input handshake message
	direction := h.hs.handshakePattern.messagePatterns[h.hs.msgPatternIdx].direction
	reading, writing := h.hs.getReadingWritingState(direction)

	var err error

	if writing { // If we write an answer at this handshake step
		hsStepResult.PayloadV2 = &PayloadV2{}
		hsStepResult.PayloadV2.ProtocolId = h.hs.handshakePattern.protocolID

		// We set the messageNametag and the handshake and transport messages
		hsStepResult.PayloadV2.MessageNametag = messageNametag
		hsStepResult.PayloadV2.HandshakeMessage, err = h.hs.processMessagePatternTokens(nil)
		if err != nil {
			return nil, err
		}

		// We write the payload by passing the messageNametag as extra additional data
		hsStepResult.PayloadV2.TransportMessage, err = h.hs.processMessagePatternPayload(transportMessage, hsStepResult.PayloadV2.MessageNametag[:])
		if err != nil {
			return nil, err
		}

	} else if reading { // If we read an answer during this handshake step
		// If the read message nametag doesn't match the expected input one we raise an error
		expectedNametag := messageNametag
		if !bytes.Equal(readPayloadV2.MessageNametag[:], expectedNametag[:]) {
			return nil, ErrUnexpectedMessageNametag
		}

		// We process the read public keys and (eventually decrypt) the read transport message
		// Since we only read, nothing meaningful (i.e. public keys) is returned
		_, err := h.hs.processMessagePatternTokens(readPayloadV2.HandshakeMessage)
		if err != nil {
			return nil, err
		}
		// We retrieve and store the (decrypted) received transport message by passing the messageNametag as extra additional data
		hsStepResult.TransportMessage, err = h.hs.processMessagePatternPayload(readPayloadV2.TransportMessage, readPayloadV2.MessageNametag[:])
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("handshake Error: neither writing or reading user")
	}

	// We increase the handshake state message pattern index to progress to next step
	h.hs.msgPatternIdx += 1

	return hsStepResult, nil
}

// Finalizes the handshake by calling Split and assigning the proper Cipher States to users
func (h *Handshake) FinalizeHandshake() (*HandshakeResult, error) {
	if h.IsComplete() {
		return h.hsResult, nil
	}

	var hsResult *HandshakeResult

	// Noise specification, Section 5:
	// Processing the final handshake message returns two CipherState objects,
	// the first for encrypting transport messages from initiator to responder,
	// and the second for messages in the other direction.

	// We call Split()
	cs1, cs2 := h.hs.ss.split()

	// Optional: We derive a secret for the nametag derivation
	nms1, nms2 := h.hs.genMessageNametagSecrets()

	// We assign the proper Cipher States
	if h.hs.initiator {
		hsResult = NewHandshakeResult(cs1, cs2)
		// and nametags secrets
		hsResult.nametagsInbound.secret = nms1
		hsResult.nametagsOutbound.secret = nms2
	} else {
		hsResult = NewHandshakeResult(cs2, cs1)
		// and nametags secrets
		hsResult.nametagsInbound.secret = nms2
		hsResult.nametagsOutbound.secret = nms1
	}

	// We initialize the message nametags inbound/outbound buffers
	hsResult.nametagsInbound.Init()
	hsResult.nametagsOutbound.Init()

	if len(h.hs.rs) == 0 {
		return nil, errors.New("invalid handshake state")
	}

	// We store the optional fields rs and h
	copy(hsResult.rs[:], h.hs.rs)
	copy(hsResult.h[:], h.hs.ss.h)

	h.hsResult = hsResult

	return hsResult, nil
}

// HandshakeComplete indicates whether the handshake process is complete or not
func (hs *Handshake) IsComplete() bool {
	return hs.hsResult != nil
}
