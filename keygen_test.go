package jwtrsa

import (
	"crypto/rsa"
	"testing"
)

func TestKeyGen(t *testing.T) {
	privateKeyStr := GenPrivateKey()
	if len(privateKeyStr) == 0 {
		t.Error("empty private key generated")
	}

	privateKey, err := ParsePrivateKey(privateKeyStr)
	if err != nil {
		t.Error(err)
	}
	publicKey, err := PublicPemFromPrivate(privateKey)
	if err != nil {
		t.Error(err)
	}
	if len(publicKey) == 0 {
		t.Error("empty public key generated")
	}
}

func TestEmptyKey(t *testing.T) {
	var nilPrivateKey *rsa.PrivateKey
	_, err := PublicPemFromPrivate(nilPrivateKey)
	if err == nil {
		t.Error("nil private key: did not receive expected error")
	}

	emptyPrivateKey := rsa.PrivateKey{}
	_, err = PublicPemFromPrivate(&emptyPrivateKey)
	if err == nil {
		t.Error("empty private key:  did not receive expected error")
	}

	publicKey := rsa.PublicKey{}
	emptyPublicKey := rsa.PrivateKey{PublicKey: publicKey}
	_, err = PublicPemFromPrivate(&emptyPublicKey)
	if err == nil {
		t.Error("empty public key: did not receive expected error")
	}

	emptyPrivKeyStr := ""
	_, err = ParsePrivateKey(emptyPrivKeyStr)
	if err == nil {
		t.Error("ParsePrivteKey: did not receive expected error")
	}
}
