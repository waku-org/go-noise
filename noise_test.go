package noise

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateRandomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestSerialization(t *testing.T) {
	handshakeMessages := make([]*NoisePublicKey, 2)

	pk1, _ := DH25519.GenerateKeypair()

	pk2, _ := DH25519.GenerateKeypair()

	handshakeMessages[0] = byteToNoisePublicKey(DH25519, pk1.Public)
	handshakeMessages[1] = byteToNoisePublicKey(DH25519, pk2.Public)

	p1 := &PayloadV2{
		ProtocolId:       Noise_K1K1_25519_ChaChaPoly_SHA256,
		HandshakeMessage: handshakeMessages,
		TransportMessage: []byte{9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	serializedPayload, err := p1.Serialize()
	require.NoError(t, err)

	deserializedPayload, err := DeserializePayloadV2(serializedPayload)
	require.NoError(t, err)
	require.Equal(t, p1, deserializedPayload)
}

func handshakeTest(t *testing.T, hsAlice *Handshake, hsBob *Handshake) {
	// ###############
	// # 1st step
	// ###############

	// By being the handshake initiator, Alice writes a Waku2 payload v2 containing her handshake message
	// and the (encrypted) transport message
	sentTransportMessage := generateRandomBytes(t, 32)
	aliceStep, err := hsAlice.Step(nil, sentTransportMessage, MessageNametag{})
	require.NoError(t, err)

	// Bob reads Alice's payloads, and returns the (decrypted) transport message Alice sent to him
	bobStep, err := hsBob.Step(aliceStep.PayloadV2, nil, MessageNametag{})
	require.NoError(t, err)

	// check:
	require.Equal(t, sentTransportMessage, bobStep.TransportMessage)

	// ###############
	// # 2nd step
	// ###############

	// At this step, Bob writes and returns a payload
	sentTransportMessage = generateRandomBytes(t, 32)
	bobStep, err = hsBob.Step(nil, sentTransportMessage, MessageNametag{})
	require.NoError(t, err)

	// While Alice reads and returns the (decrypted) transport message
	aliceStep, err = hsAlice.Step(bobStep.PayloadV2, nil, MessageNametag{})
	require.NoError(t, err)

	// check:
	require.Equal(t, sentTransportMessage, aliceStep.TransportMessage)

	// ###############
	// # 3rd step
	// ###############

	// Similarly as in first step, Alice writes a Waku2 payload containing the handshake message and the (encrypted) transport message
	sentTransportMessage = generateRandomBytes(t, 32)
	aliceStep, err = hsAlice.Step(nil, sentTransportMessage, MessageNametag{})
	require.NoError(t, err)

	// Bob reads Alice's payloads, and returns the (decrypted) transport message Alice sent to him
	bobStep, err = hsBob.Step(aliceStep.PayloadV2, nil, MessageNametag{})
	require.NoError(t, err)

	// check:
	require.Equal(t, sentTransportMessage, bobStep.TransportMessage)

	_, err = hsAlice.FinalizeHandshake()
	require.NoError(t, err)

	_, err = hsBob.FinalizeHandshake()
	require.NoError(t, err)

	// Note that for this handshake pattern, no more message patterns are left for processing
	// We test that extra calls to stepHandshake do not affect parties' handshake states
	require.True(t, hsAlice.IsComplete())
	require.True(t, hsBob.IsComplete())

	_, err = hsAlice.Step(nil, generateRandomBytes(t, 32), MessageNametag{})
	require.ErrorIs(t, err, ErrHandshakeComplete)

	_, err = hsBob.Step(nil, generateRandomBytes(t, 32), MessageNametag{})
	require.ErrorIs(t, err, ErrHandshakeComplete)

	// #########################
	// After Handshake
	// #########################

	// We test read/write of random messages exchanged between Alice and Bob

	defaultMessageNametagBuffer := NewMessageNametagBuffer(nil)

	aliceHSResult, err := hsAlice.FinalizeHandshake()
	require.NoError(t, err)

	bobHSResult, err := hsBob.FinalizeHandshake()
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		// Alice writes to Bob
		message := generateRandomBytes(t, 32)

		encryptedPayload, err := aliceHSResult.WriteMessage(message, defaultMessageNametagBuffer)
		require.NoError(t, err)

		plaintext, err := bobHSResult.ReadMessage(encryptedPayload, defaultMessageNametagBuffer)
		require.NoError(t, err)

		require.Equal(t, message, plaintext)

		// Bob writes to Alice
		message = generateRandomBytes(t, 32)

		encryptedPayload, err = bobHSResult.WriteMessage(message, defaultMessageNametagBuffer)
		require.NoError(t, err)

		plaintext, err = aliceHSResult.ReadMessage(encryptedPayload, defaultMessageNametagBuffer)
		require.NoError(t, err)

		require.Equal(t, message, plaintext)
	}
}

func TestNoiseXXHandshakeRoundtrip(t *testing.T) {
	aliceKP, _ := DH25519.GenerateKeypair()
	bobKP, _ := DH25519.GenerateKeypair()

	hsAlice, err := NewHandshake_XX_25519_ChaChaPoly_SHA256(aliceKP, true, nil)
	require.NoError(t, err)

	hsBob, err := NewHandshake_XX_25519_ChaChaPoly_SHA256(bobKP, false, nil)
	require.NoError(t, err)

	handshakeTest(t, hsAlice, hsBob)
}

func TestNoiseXXpsk0HandshakeRoundtrip(t *testing.T) {
	aliceKP, _ := DH25519.GenerateKeypair()
	bobKP, _ := DH25519.GenerateKeypair()

	// We generate a random psk
	psk := generateRandomBytes(t, 32)

	hsAlice, err := NewHandshake_XXpsk0_25519_ChaChaPoly_SHA256(aliceKP, true, psk, nil)
	require.NoError(t, err)

	hsBob, err := NewHandshake_XXpsk0_25519_ChaChaPoly_SHA256(bobKP, false, psk, nil)
	require.NoError(t, err)

	handshakeTest(t, hsAlice, hsBob)
}

func TestNoiseK1K1HandshakeRoundtrip(t *testing.T) {
	aliceKP, _ := DH25519.GenerateKeypair()
	bobKP, _ := DH25519.GenerateKeypair()

	hsAlice, err := NewHandshake_K1K1_25519_ChaChaPoly_SHA256(aliceKP, true, bobKP.Public, nil)
	require.NoError(t, err)

	hsBob, err := NewHandshake_K1K1_25519_ChaChaPoly_SHA256(bobKP, false, aliceKP.Public, nil)
	require.NoError(t, err)

	handshakeTest(t, hsAlice, hsBob)
}

func TestNoiseXK1HandshakeRoundtrip(t *testing.T) {
	aliceKP, _ := DH25519.GenerateKeypair()
	bobKP, _ := DH25519.GenerateKeypair()

	hsAlice, err := NewHandshake_XK1_25519_ChaChaPoly_SHA256(aliceKP, true, bobKP.Public, nil)
	require.NoError(t, err)

	hsBob, err := NewHandshake_XK1_25519_ChaChaPoly_SHA256(bobKP, false, bobKP.Public, nil)
	require.NoError(t, err)

	handshakeTest(t, hsAlice, hsBob)
}

func TestPKCSPaddingUnpadding(t *testing.T) {
	maxMessageLength := 3 * NoisePaddingBlockSize
	for messageLen := 0; messageLen <= maxMessageLength; messageLen++ {
		message := generateRandomBytes(t, messageLen)
		padded, err := PKCS7_Pad(message, NoisePaddingBlockSize)
		require.NoError(t, err)
		unpadded, err := PKCS7_Unpad(padded, NoisePaddingBlockSize)
		require.NoError(t, err)

		require.Greater(t, len(padded), 0)
		require.Equal(t, len(padded)%NoisePaddingBlockSize, 0)
		require.Equal(t, message, unpadded)
	}
}
