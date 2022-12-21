package noise

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
)

// Waku Noise Protocols for Waku Payload Encryption
// Noise module implementing the Noise State Objects and ChaChaPoly encryption/decryption primitives
// See spec for more details:
// https://github.com/vacp2p/rfc/tree/master/content/docs/rfcs/35
//
// Implementation partially inspired by noise-libp2p and js-libp2p-noise
// https://github.com/status-im/nim-libp2p/blob/master/libp2p/protocols/secure/noise.nim
// https://github.com/ChainSafe/js-libp2p-noise

/*
# Noise state machine primitives

# Overview :
# - Alice and Bob process (i.e. read and write, based on their role) each token appearing in a handshake pattern, consisting of pre-message and message patterns;
# - Both users initialize and update according to processed tokens a Handshake State, a Symmetric State and a Cipher State;
# - A preshared key psk is processed by calling MixKeyAndHash(psk);
# - When an ephemeral public key e is read or written, the handshake hash value h is updated by calling mixHash(e); If the handshake expects a psk, MixKey(e) is further called
# - When an encrypted static public key s or a payload message m is read, it is decrypted with decryptAndHash;
# - When a static public key s or a payload message is written, it is encrypted with encryptAndHash;
# - When any Diffie-Hellman token ee, es, se, ss is read or written, the chaining key ck is updated by calling MixKey on the computed secret;
# - If all tokens are processed, users compute two new Cipher States by calling Split;
# - The two Cipher States obtained from Split are used to encrypt/decrypt outbound/inbound messages.

#################################
# Cipher State Primitives
#################################
*/

const nonceMax = math.MaxUint64 - 1 // max is reserved

func isEmptyKey(k []byte) bool {
	return len(k) == 0
}

// The Cipher State as in https://noiseprotocol.org/noise.html#the-cipherstate-object
// Contains an encryption key k and a nonce n (used in Noise as a counter)
type CipherState struct {
	k        []byte
	n        uint64
	cipherFn func([]byte) (cipher.AEAD, error)
}

func NewCipherState(k []byte, cipherFn func([]byte) (cipher.AEAD, error)) *CipherState {
	return &CipherState{
		k:        k,
		cipherFn: cipherFn,
	}
}

func (c *CipherState) Equals(b *CipherState) bool {
	return bytes.Equal(c.k[:], b.k[:]) && c.n == b.n
}

// Checks if a Cipher State has an encryption key set
func (c *CipherState) hasKey() bool {
	return !isEmptyKey(c.k)
}

func (cs *CipherState) nonce() []byte {
	// RFC7539 specifies 12 bytes for nonce.
	// TODO: extract this to function setup when creating handshake pattern
	var nonceBytes [12]byte
	binary.LittleEndian.PutUint64(nonceBytes[4:], cs.n)
	return nonceBytes[:]
}

// Encrypts a plaintext using key material in a Noise Cipher State
// The CipherState is updated increasing the nonce (used as a counter in Noise) by one
func (cs *CipherState) encryptWithAd(ad []byte, plaintext []byte) ([]byte, error) {
	// We raise an error if encryption is called using a Cipher State with nonce greater than  MaxNonce
	if cs.n > nonceMax {
		return nil, errors.New("noise max nonce value reached")
	}

	var ciphertext []byte

	if cs.hasKey() {
		c, err := cs.cipherFn(cs.k)
		if err != nil {
			panic(err)
		}

		// If an encryption key is set in the Cipher state, we proceed with encryption
		ciphertext = c.Seal(nil, cs.nonce(), plaintext, ad)

		// We increase the Cipher state nonce
		cs.n++

		// If the nonce is greater than the maximum allowed nonce, we raise an exception
		if cs.n > nonceMax {
			return nil, errors.New("noise max nonce value reached")
		}
	} else {
		// Otherwise we return the input plaintext according to specification http://www.noiseprotocol.org/noise.html#the-cipherstate-object
		ciphertext = plaintext
	}

	return ciphertext, nil
}

// Decrypts a ciphertext using key material in a Noise Cipher State
// The CipherState is updated increasing the nonce (used as a counter in Noise) by one
func (cs *CipherState) decryptWithAd(ad []byte, ciphertext []byte) ([]byte, error) {
	// We raise an error if encryption is called using a Cipher State with nonce greater than  MaxNonce
	if cs.n > nonceMax {
		return nil, errors.New("noise max nonce value reached")
	}
	if cs.hasKey() {
		c, err := cs.cipherFn(cs.k)
		if err != nil {
			panic(err)
		}

		plaintext, err := c.Open(nil, cs.nonce(), ciphertext, ad)
		if err != nil {
			return nil, err
		}

		// We increase the Cipher state nonce
		cs.n++

		// If the nonce is greater than the maximum allowed nonce, we raise an exception
		if cs.n > nonceMax {
			return nil, errors.New("noise max nonce value reached")
		}

		return plaintext, nil
	} else {
		// Otherwise we return the input ciphertext according to specification
		// http://www.noiseprotocol.org/noise.html#the-cipherstate-object
		return ciphertext, nil
	}
}

func hashProtocol(hsPattern HandshakePattern) []byte {
	// If protocol_name is less than or equal to HASHLEN bytes in length,
	// sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
	// Otherwise sets h = HASH(protocol_name).
	protocolName := []byte(hsPattern.name)

	if len(protocolName) <= hsPattern.hashFn().Size() {
		result := make([]byte, hsPattern.hashFn().Size())
		copy(result, protocolName)
		return result
	} else {
		h := hsPattern.hashFn()
		h.Write([]byte(hsPattern.name))
		return h.Sum(nil)
	}
}

// The Symmetric State as in https://noiseprotocol.org/noise.html#the-symmetricstate-object
// Contains a Cipher State cs, the chaining key ck and the handshake hash value h
type SymmetricState struct {
	cs        *CipherState
	hsPattern HandshakePattern
	h         []byte // handshake hash
	ck        []byte // chaining key
}

func NewSymmetricState(hsPattern HandshakePattern) *SymmetricState {
	h := hashProtocol(hsPattern)

	s := &SymmetricState{
		cs:        NewCipherState([]byte{}, hsPattern.cipherFn),
		hsPattern: hsPattern,
	}

	s.h = make([]byte, len(h))
	copy(s.h, h)

	s.ck = make([]byte, len(h))
	copy(s.ck, h)

	return s
}

func (s *SymmetricState) Equals(b *SymmetricState) bool {
	return b.cs.Equals(s.cs) && bytes.Equal(s.ck, b.ck) && bytes.Equal(s.h, b.h) && s.hsPattern.Equals(b.hsPattern)
}

// MixKey as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
// Updates a Symmetric state chaining key and symmetric state
func (s *SymmetricState) mixKey(inputKeyMaterial []byte) {
	// We derive two keys using HKDF
	keyLen := s.hsPattern.hashFn().Size()
	output := getHKDF(s.hsPattern.hashFn, s.ck, inputKeyMaterial, keyLen*2)
	ck := output[:keyLen]
	tempK := output[keyLen:]
	// We update ck and the Cipher state's key k using the output of HDKF
	s.cs = NewCipherState(tempK, s.hsPattern.cipherFn)
	s.ck = ck
}

// MixHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
// Hashes data into a Symmetric State's handshake hash value h
func (s *SymmetricState) mixHash(data []byte) {
	// We hash the previous handshake hash and input data and store the result in the Symmetric State's handshake hash value
	h := s.hsPattern.hashFn()
	h.Write(s.h[:])
	h.Write(data)
	s.h = h.Sum(nil)
}

// mixKeyAndHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
// Combines MixKey and MixHash
func (s *SymmetricState) mixKeyAndHash(inputKeyMaterial []byte) {
	// Derives 3 keys using HKDF, the chaining key and the input key material
	keyLen := s.hsPattern.hashFn().Size()
	output := getHKDF(s.hsPattern.hashFn, s.ck, inputKeyMaterial, keyLen*3)
	tmpKey0 := output[:keyLen]
	tmpKey1 := output[keyLen : keyLen*2]
	tmpKey2 := output[keyLen*2:]

	// Sets the chaining key
	s.ck = tmpKey0
	// Updates the handshake hash value
	s.mixHash(tmpKey1)
	// Updates the Cipher state's key
	// Note for later support of 512 bits hash functions: "If HASHLEN is 64, then truncates tempKeys[2] to 32 bytes."
	s.cs = NewCipherState(tmpKey2, s.hsPattern.cipherFn)
}

// EncryptAndHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
// Combines encryptWithAd and mixHash
// Note that by setting extraAd, it is possible to pass extra additional data that will be concatenated to the ad specified by Noise (can be used to authenticate messageNametag)
func (s *SymmetricState) encryptAndHash(plaintext []byte, extraAd []byte) ([]byte, error) {
	// The additional data
	ad := append([]byte(nil), s.h[:]...)
	ad = append(ad, extraAd...)
	// Note that if an encryption key is not set yet in the Cipher state, ciphertext will be equal to plaintext
	ciphertext, err := s.cs.encryptWithAd(ad, plaintext)
	if err != nil {
		return nil, err
	}
	// We call mixHash over the result
	s.mixHash(ciphertext)

	return ciphertext, nil
}

// DecryptAndHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
// Combines decryptWithAd and mixHash
func (s *SymmetricState) decryptAndHash(ciphertext []byte, extraAd []byte) ([]byte, error) {
	// The additional data
	ad := append([]byte(nil), s.h[:]...)
	ad = append(ad, extraAd...)

	// Note that if an encryption key is not set yet in the Cipher state, plaintext will be equal to ciphertext
	plaintext, err := s.cs.decryptWithAd(ad, ciphertext)
	if err != nil {
		return nil, err
	}

	// According to specification, the ciphertext enters mixHash (and not the plaintext)
	s.mixHash(ciphertext)

	return plaintext, nil
}

// Split as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
// Once a handshake is complete, returns two Cipher States to encrypt/decrypt outbound/inbound messages
func (s *SymmetricState) split() (*CipherState, *CipherState) {
	// Derives 2 keys using HKDF and the chaining key
	keyLen := s.hsPattern.hashFn().Size()
	output := getHKDF(s.hsPattern.hashFn, s.ck, []byte{}, keyLen*2)
	tmpKey1 := output[:keyLen]
	tmpKey2 := output[keyLen:]
	// Returns a tuple of two Cipher States initialized with the derived keys
	return NewCipherState(tmpKey1, s.hsPattern.cipherFn), NewCipherState(tmpKey2, s.hsPattern.cipherFn)
}
