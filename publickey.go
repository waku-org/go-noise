package noise

import (
	"bytes"
	"errors"
)

// A Noise public key is a public key exchanged during Noise handshakes (no private part)
// This follows https://rfc.vac.dev/spec/35/#public-keys-serialization
// pk contains the X coordinate of the public key, if unencrypted (this implies flag = 0)
// or the encryption of the X coordinate concatenated with the authorization tag, if encrypted (this implies flag = 1)
// Note: besides encryption, flag can be used to distinguish among multiple supported Elliptic Curves
type NoisePublicKey struct {
	Flag   byte
	Public []byte
}

func NewNoisePublicKey(flag byte, public []byte) *NoisePublicKey {
	return &NoisePublicKey{
		Flag:   flag,
		Public: public,
	}
}

func byteToNoisePublicKey(dhKey DHKey, input []byte) *NoisePublicKey {
	flag := byte(0)
	if len(input) > dhKey.DHLen() {
		flag = 1
	}

	return &NoisePublicKey{
		Flag:   flag,
		Public: input,
	}
}

// Equals checks equality between two Noise public keys
func (pk *NoisePublicKey) Equals(pk2 *NoisePublicKey) bool {
	return pk.Flag == pk2.Flag && bytes.Equal(pk.Public, pk2.Public)
}

type SerializedNoisePublicKey []byte

// Serialize converts a Noise public key to a stream of bytes as in
// https://rfc.vac.dev/spec/35/#public-keys-serialization
func (pk *NoisePublicKey) Serialize() SerializedNoisePublicKey {
	// Public key is serialized as (flag || pk)
	// Note that pk contains the X coordinate of the public key if unencrypted
	// or the encryption concatenated with the authorization tag if encrypted
	serializedPK := make([]byte, len(pk.Public)+1)
	serializedPK[0] = pk.Flag
	copy(serializedPK[1:], pk.Public)

	return serializedPK
}

// Unserialize converts a serialized Noise public key to a NoisePublicKey object as in
// https://rfc.vac.dev/spec/35/#public-keys-serialization
func (s SerializedNoisePublicKey) Unserialize() (*NoisePublicKey, error) {
	if len(s) <= 1 {
		return nil, errors.New("invalid serialized public key length")
	}

	pubk := &NoisePublicKey{}
	pubk.Flag = s[0]
	if !(pubk.Flag == 0 || pubk.Flag == 1) {
		return nil, errors.New("invalid flag in serialized public key")
	}

	pubk.Public = s[1:]

	return pubk, nil
}

// Encrypt encrypts a Noise public key using a Cipher State
func (pk *NoisePublicKey) Encrypt(state *CipherState) error {
	if pk.Flag == 0 {
		// Authorization tag is appended to output
		encPk, err := state.encryptWithAd(nil, pk.Public)
		if err != nil {
			return err
		}
		pk.Flag = 1
		pk.Public = encPk
	}

	return nil
}

// Decrypts decrypts a Noise public key using a Cipher State
func (pk *NoisePublicKey) Decrypt(state *CipherState) error {
	if pk.Flag == 1 {
		decPk, err := state.decryptWithAd(nil, pk.Public) // encrypted pk should contain the auth tag
		if err != nil {
			return err
		}
		pk.Flag = 0
		pk.Public = decPk
	}

	return nil
}
