package ecdh

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
)

// Sign sign random generated hash by private key, returns signed hash, raw hash
func (kp *KeyPair) Sign() (string, string, string, error) {
	hash := make([]byte, 64)
	_, err := rand.Reader.Read(hash)
	if err != nil {
		return "", "", "", fmt.Errorf("Generate random hash: %v", err)
	}

	R, S, err := kp.SignCustomCache(hash)
	if err != nil {
		return "", "", "", err
	}

	return R, S, string(hash), nil
}

// Sign sign hash by private key, returns signed hash
func (kp *KeyPair) SignCustomCache(hash []byte) (string, string, error) {
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey(), hash)
	if err != nil {
		return "", "", fmt.Errorf("Cannot sign: %v", err)
	}

	return r.String(), s.String(), nil
}

// Verify signed hash by public key
func (kp *KeyPair) Verify(R, S, hash, publicKeyStr string) (bool, error) {
	publicKey, err := UnmarshalPublicCustomCurve(kp.curve, publicKeyStr)
	if err != nil {
		return false, fmt.Errorf("Cannot unmarshal publicKey: %v", err)
	}

	return kp.VerifyCustomPublic(R, S, hash, publicKey)
}

// VerifyCustomPublic signed hash by public key
func (kp *KeyPair) VerifyCustomPublic(rStr, sStr, hash string, publicKey ecdsa.PublicKey) (bool, error) {
	R, isOk := big.NewInt(0).SetString(rStr, 10)
	if !isOk {
		return false, fmt.Errorf("Invalid R: %s", rStr)
	}

	S, isOk := big.NewInt(0).SetString(sStr, 10)
	if !isOk {
		return false, fmt.Errorf("Invalid S: %s", sStr)
	}

	isOk = ecdsa.Verify(&publicKey, []byte(hash), R, S)

	return isOk, nil
}
