package jwtrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenPrivateKey returns a RSA private key as a string
func GenPrivateKey() string {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return string(pemData)
}

// PublicPemFromPrivate takes an RSA Private Key and returns the Public Key in PEM format.
func PublicPemFromPrivate(priv *rsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", errors.New("unable to parse private key")
	}

	// 1. Extract the public key from the private key struct
	pubKey := &priv.PublicKey

	// 2. Convert the public key to PKIX, ASN.1 DER form
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	// 3. Encode the DER bytes into PEM format
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// ParsePrivateKey receives a private key string and returns *rsa.PrivateKey or error
func ParsePrivateKey(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
