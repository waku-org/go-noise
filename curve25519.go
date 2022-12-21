package noise

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

type dh25519 struct {
	DHKey
}

func (d dh25519) GenerateKeypair() (Keypair, error) {
	privkey := make([]byte, DH25519.DHLen())
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		return Keypair{}, err
	}
	return d.GenerateKeyPairFromPrivateKey(privkey)
}

func (d dh25519) DH(privkey, pubkey []byte) ([]byte, error) {
	return curve25519.X25519(privkey, pubkey)
}

func (d dh25519) DHLen() int { return 32 }

func (d dh25519) GenerateKeyPairFromPrivateKey(privkey []byte) (Keypair, error) {
	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: privkey, Public: pubkey}, nil
}

var DH25519 = dh25519{}
