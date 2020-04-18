package ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// KeyPair crypto key pair
type KeyPair struct {
	curve      elliptic.Curve
	privateKey *ecdsa.PrivateKey
}

// PrivateKey return private key from key pair
func (kp *KeyPair) PrivateKey() *ecdsa.PrivateKey {
	return kp.privateKey
}

// PublicKey return public key from key pair
func (kp *KeyPair) PublicKey() ecdsa.PublicKey {
	return kp.privateKey.PublicKey
}

// GenerateKey generate new random key pair
func GenerateKey() (*KeyPair, error) {
	return GenerateKeyCustomCurve(elliptic.P256())
}

// GenerateKey generate new random key pair by custom curve
func GenerateKeyCustomCurve(curve elliptic.Curve) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("GenerateKey: %v", err)
	}

	kp := &KeyPair{
		curve:      curve,
		privateKey: privateKey,
	}

	return kp, nil
}

// Unmarshal restore key pair from privateKey and publicKey string
func Unmarshal(privateKey, publicKey string) (*KeyPair, error) {
	return UnmarshalCustomCurve(elliptic.P256(), privateKey, publicKey)
}

// UnmarshalCustomCurve restore key pair from privateKey and publicKey string by custom curve
func UnmarshalCustomCurve(curve elliptic.Curve, privateKeyStr, publicKeyStr string) (*KeyPair, error) {
	D := new(big.Int)
	_, isOk := D.SetString(privateKeyStr, 10)
	if !isOk {
		return nil, fmt.Errorf("Invalid private key")
	}

	publicKey, err := UnmarshalPublicCustomCurve(curve, publicKeyStr)
	if err != nil {
		return nil, err
	}

	privateKey := &ecdsa.PrivateKey{PublicKey: publicKey, D: D}
	kp := &KeyPair{curve: curve, privateKey: privateKey}

	return kp, nil
}

// UnmarshalPublic restore public key from string
func UnmarshalPublic(publicKeyStr string) (ecdsa.PublicKey, error) {
	return UnmarshalPublicCustomCurve(elliptic.P256(), publicKeyStr)
}

// UnmarshalPublic restore public key from string by custom curve
func UnmarshalPublicCustomCurve(curve elliptic.Curve, publicKeyStr string) (ecdsa.PublicKey, error) {
	X, Y := elliptic.Unmarshal(curve, []byte(publicKeyStr))
	if X == nil {
		return ecdsa.PublicKey{}, fmt.Errorf("Invalid publicKey: %s", publicKeyStr)
	}

	publicKey := ecdsa.PublicKey{Curve: curve, X: X, Y: Y}

	return publicKey, nil
}

// Marshal transform key pair to strings for transporting and storing
func (kp *KeyPair) Marshal() (privateKey, publicKey string) {
	privateKey = kp.privateKey.D.String()
	publicKey = string(elliptic.Marshal(kp.curve, kp.PublicKey().X, kp.PublicKey().Y))
	return
}

// GenerateSecret generate shared secret
func (kp *KeyPair) GenerateSecret(anotherPublicKey ecdsa.PublicKey) (*SharedSecret, error) {
	x, _ := kp.curve.ScalarMult(anotherPublicKey.X, anotherPublicKey.Y, kp.privateKey.D.Bytes())
	if x == nil {
		return nil, errors.New("GenerateSecret failed")
	}

	sharedSecret, err := NewSharedSecret(x.String()[0:32])
	if err != nil {
		return nil, fmt.Errorf("NewSharedSecret: %v", err)
	}

	return sharedSecret, nil
}
