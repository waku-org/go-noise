package noise

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

const MaxUint8 = 1<<8 - 1

// PayloadV2 defines an object for Waku payloads with version 2 as in
// https://rfc.vac.dev/spec/35/#public-keys-serialization
// It contains a protocol ID field, the handshake message (for Noise handshakes) and
// a transport message (for Noise handshakes and ChaChaPoly encryptions)
type PayloadV2 struct {
	ProtocolId       byte
	HandshakeMessage []*NoisePublicKey
	TransportMessage []byte
	MessageNametag   MessageNametag
}

// Checks equality between two PayloadsV2 objects
func (p *PayloadV2) Equals(p2 *PayloadV2) bool {
	if p.ProtocolId != p2.ProtocolId || !bytes.Equal(p.TransportMessage, p2.TransportMessage) {
		return false
	}

	for _, p1 := range p.HandshakeMessage {
		for _, p2 := range p2.HandshakeMessage {
			if !p1.Equals(p2) {
				return false
			}
		}
	}

	return true
}

// Serializes a PayloadV2 object to a byte sequences according to https://rfc.vac.dev/spec/35/
// The output serialized payload concatenates the input PayloadV2 object fields as
// payload = ( protocolId || serializedHandshakeMessageLen || serializedHandshakeMessage || transportMessageLen || transportMessage)
// The output can be then passed to the payload field of a WakuMessage https://rfc.vac.dev/spec/14/
func (p *PayloadV2) Serialize() ([]byte, error) {
	// We collect public keys contained in the handshake message

	// According to https://rfc.vac.dev/spec/35/, the maximum size for the handshake message is 256 bytes, that is
	// the handshake message length can be represented with 1 byte only. (its length can be stored in 1 byte)
	// However, to ease public keys length addition operation, we declare it as int and later cast to uit8
	serializedHandshakeMessageLen := 0
	// This variables will store the concatenation of the serializations of all public keys in the handshake message
	serializedHandshakeMessage := make([]byte, 0, 256)
	serializedHandshakeMessageBuffer := bytes.NewBuffer(serializedHandshakeMessage)

	for _, pk := range p.HandshakeMessage {
		serializedPK := pk.Serialize()
		serializedHandshakeMessageLen += len(serializedPK)
		if _, err := serializedHandshakeMessageBuffer.Write(serializedPK); err != nil {
			return nil, err
		}
		if serializedHandshakeMessageLen > MaxUint8 {
			return nil, errors.New("too many public keys in handshake message")
		}
	}

	// The output payload as in https://rfc.vac.dev/spec/35/. We concatenate all the PayloadV2 fields as
	// payload = ( protocolId || serializedHandshakeMessageLen || serializedHandshakeMessage || transportMessageLen || transportMessage)

	// We declare it as a byte sequence of length accordingly to the PayloadV2 information read
	payload := make([]byte, 0, MessageNametagLength+
		1+ // 1 byte for protocol ID
		1+ // 1 byte for length of serializedHandshakeMessage field
		serializedHandshakeMessageLen+ // serializedHandshakeMessageLen bytes for serializedHandshakeMessage
		8+ // 8 bytes for transportMessageLen
		len(p.TransportMessage), // transportMessageLen bytes for transportMessage
	)

	payloadBuf := bytes.NewBuffer(payload)

	if _, err := payloadBuf.Write(p.MessageNametag[:]); err != nil {
		return nil, err
	}

	//  The protocol ID (1 byte) and handshake message length (1 byte) can be directly casted to byte to allow direct copy to the payload byte sequence
	if err := payloadBuf.WriteByte(p.ProtocolId); err != nil {
		return nil, err
	}

	if err := payloadBuf.WriteByte(byte(serializedHandshakeMessageLen)); err != nil {
		return nil, err
	}

	if _, err := payloadBuf.Write(serializedHandshakeMessageBuffer.Bytes()); err != nil {
		return nil, err
	}

	TransportMessageLen := uint64(len(p.TransportMessage))
	if err := binary.Write(payloadBuf, binary.LittleEndian, TransportMessageLen); err != nil {
		return nil, err
	}

	if _, err := payloadBuf.Write(p.TransportMessage); err != nil {
		return nil, err
	}

	return payloadBuf.Bytes(), nil
}

const ChaChaPolyTagSize = byte(16)

// Deserializes a byte sequence to a PayloadV2 object according to https://rfc.vac.dev/spec/35/.
// The input serialized payload concatenates the output PayloadV2 object fields as
// payload = ( protocolId || serializedHandshakeMessageLen || serializedHandshakeMessage || transportMessageLen || transportMessage)
func DeserializePayloadV2(payload []byte) (*PayloadV2, error) {
	payloadBuf := bytes.NewBuffer(payload)

	result := &PayloadV2{}

	// We start by reading the messageNametag
	if err := binary.Read(payloadBuf, binary.BigEndian, &result.MessageNametag); err != nil {
		return nil, err
	}

	// We read the Protocol ID
	if err := binary.Read(payloadBuf, binary.BigEndian, &result.ProtocolId); err != nil {
		return nil, err
	}

	if !IsProtocolIDSupported(result.ProtocolId) {
		return nil, errors.New("unsupported protocol")
	}

	// We read the Handshake Message length (1 byte)
	var handshakeMessageLen byte
	if err := binary.Read(payloadBuf, binary.BigEndian, &handshakeMessageLen); err != nil {
		return nil, err
	}
	if handshakeMessageLen > MaxUint8 {
		return nil, errors.New("too many public keys in handshake message")
	}

	written := byte(0)
	var handshakeMessages []*NoisePublicKey
	for written < handshakeMessageLen {
		// We obtain the current Noise Public key encryption flag
		flag, err := payloadBuf.ReadByte()
		if err != nil {
			return nil, err
		}

		if flag == 0 {
			// If the key is unencrypted, we only read the X coordinate of the EC public key and we deserialize into a Noise Public Key
			pkLen := ed25519.PublicKeySize
			var pkBytes SerializedNoisePublicKey = make([]byte, pkLen)
			if err := binary.Read(payloadBuf, binary.BigEndian, &pkBytes); err != nil {
				return nil, err
			}

			serializedPK := SerializedNoisePublicKey(make([]byte, ed25519.PublicKeySize+1))
			serializedPK[0] = flag
			copy(serializedPK[1:], pkBytes)

			pk, err := serializedPK.Unserialize()
			if err != nil {
				return nil, err
			}

			handshakeMessages = append(handshakeMessages, pk)
			written += uint8(1 + pkLen)
		} else if flag == 1 {
			// If the key is encrypted, we only read the encrypted X coordinate and the authorization tag, and we deserialize into a Noise Public Key
			pkLen := ed25519.PublicKeySize + ChaChaPolyTagSize
			// TODO: duplicated code: ==============

			var pkBytes SerializedNoisePublicKey = make([]byte, pkLen)
			if err := binary.Read(payloadBuf, binary.BigEndian, &pkBytes); err != nil {
				return nil, err
			}

			serializedPK := SerializedNoisePublicKey(make([]byte, ed25519.PublicKeySize+1))
			serializedPK[0] = flag
			copy(serializedPK[1:], pkBytes)

			pk, err := serializedPK.Unserialize()
			if err != nil {
				return nil, err
			}

			handshakeMessages = append(handshakeMessages, pk)
			written += uint8(1 + pkLen)
			// TODO: duplicated
		} else {
			return nil, errors.New("invalid flag for Noise public key")
		}
	}

	result.HandshakeMessage = handshakeMessages

	var TransportMessageLen uint64
	if err := binary.Read(payloadBuf, binary.LittleEndian, &TransportMessageLen); err != nil {
		return nil, err
	}

	result.TransportMessage = make([]byte, TransportMessageLen)
	if err := binary.Read(payloadBuf, binary.BigEndian, &result.TransportMessage); err != nil {
		return nil, err
	}

	return result, nil
}
