package noise

import (
	"bytes"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

type DHKey interface {
	GenerateKeypair() (Keypair, error)
	DH(privkey, pubkey []byte) ([]byte, error)
	DHLen() int
}

type Keypair struct {
	Private []byte
	Public  []byte
}

func (k Keypair) IsDefault() bool {
	return k.Equals(Keypair{})
}

func (k Keypair) Equals(b Keypair) bool {
	return bytes.Equal(k.Private, b.Private) && bytes.Equal(k.Public, b.Public)
}

func getHKDF(h func() hash.Hash, ck []byte, ikm []byte, numBytes int) []byte {
	hkdf := hkdf.New(h, ikm, ck, nil)
	result := make([]byte, numBytes)
	_, _ = io.ReadFull(hkdf, result)
	return result
}

// CommitPublicKey commits a public key pk for randomness r as H(pk || s)
func CommitPublicKey(h func() hash.Hash, publicKey []byte, r []byte) []byte {
	input := []byte{}
	input = append(input, []byte(publicKey)...)
	input = append(input, r...)

	hash := h()
	hash.Write(input)
	return hash.Sum(nil)
}
