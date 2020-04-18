package ecdh

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/matryer/is"
)

func TestSecret(t *testing.T) {
	is := is.New(t)

	alice, err := GenerateKey()
	is.NoErr(err)

	bob, err := GenerateKey()
	is.NoErr(err)

	k1, err := alice.GenerateSecret(bob.PublicKey())
	is.NoErr(err)

	k2, err := bob.GenerateSecret(alice.PublicKey())
	is.NoErr(err)

	is.Equal(k1.Secret, k2.Secret)
}

func TestMarshal(t *testing.T) {
	is := is.New(t)

	key, err := GenerateKey()
	is.NoErr(err)

	priStr, pubStr := key.Marshal()

	keyUn, err := Unmarshal(priStr, pubStr)
	is.NoErr(err)

	is.Equal(key, keyUn)
}

func TestSign(t *testing.T) {
	is := is.New(t)

	key, err := GenerateKey()
	is.NoErr(err)

	r, s, hash, err := key.Sign()
	is.NoErr(err)

	_, publicKey := key.Marshal()

	isOk, err := key.Verify(r, s, hash, publicKey)
	is.NoErr(err)

	is.True(isOk)
}

func TestCrypt(t *testing.T) {
	is := is.New(t)

	alice, err := GenerateKey()
	is.NoErr(err)

	bob, err := GenerateKey()
	is.NoErr(err)

	secret, err := alice.GenerateSecret(bob.PublicKey())
	is.NoErr(err)

	randMessageRaw := make([]byte, 256)
	_, err = io.ReadFull(rand.Reader, randMessageRaw)
	is.NoErr(err)
	randMessage := string(randMessageRaw)
	// randMessage := "Hello, *шифропанки*!"

	encrypted, err := secret.Encrypt(randMessage)
	is.NoErr(err)

	original, err := secret.Decrypt(encrypted)
	is.NoErr(err)

	is.Equal(original, randMessage)
}
