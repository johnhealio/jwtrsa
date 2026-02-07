package jwtrsa

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func genKeys() (string, string) {
	privStr := GenPrivateKey()

	privKey, err := ParsePrivateKey(privStr)
	if err != nil {
		return "", ""
	}
	pubKey, err := PublicPemFromPrivate(privKey)
	if err != nil {
		return "", ""
	}
	return privStr, pubKey
}

// Helper to create a signed token for testing
func createToken(privB64 string, claims jwt.MapClaims) string {
	bytes, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return ""
	}
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(bytes)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := token.SignedString(key)
	return s
}

func TestValidator_Validate(t *testing.T) {
	privKey, pubKey := genKeys()

	iss := "MyIssuer"
	aud := "MyAudience"
	val, err := NewValidator(pubKey, iss, aud)
	if err != nil {
		t.Fatalf(err.Error())
	}

	err = testUserOk(privKey, val, iss, aud)
	if err != nil {
		t.Error(err.Error())
	}
	err = testUserEmpty(privKey, val, iss, aud)
	if err != nil {
		t.Error(err.Error())
	}
	err = testIssNotOk(privKey, val, aud)
	if err != nil {
		t.Error(err.Error())
	}
	err = testAudNotOk(privKey, val, iss)
	if err != nil {
		t.Error(err.Error())
	}
	err = testOtherKey(val, iss, aud)
	if err != nil {
		t.Error(err.Error())
	}
	err = testExpired(privKey, val, iss, aud)
	if err != nil {
		t.Error(err.Error())
	}

}

func testUserOk(pk string, val *Validator, iss string, aud string) error {
	userIn := "abc_123"
	token := createToken(pk, jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": userIn,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	userOut, err := val.Validate(token)
	if err != nil {
		return fmt.Errorf("validation fail, %v", err)
	}
	if userIn != userOut {
		return fmt.Errorf("user does not match")
	}
	return nil
}

func testUserEmpty(pk string, val *Validator, iss string, aud string) error {
	userIn := ""
	token := createToken(pk, jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": userIn,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := val.Validate(token)
	if err == nil {
		return fmt.Errorf("did not receive expected error")
	}
	return nil
}

func testIssNotOk(pk string, val *Validator, aud string) error {
	userIn := "abc_123"
	token := createToken(pk, jwt.MapClaims{
		"iss": "notvalid",
		"aud": aud,
		"sub": userIn,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := val.Validate(token)
	if err == nil {
		return fmt.Errorf("did not receive the expected error")
	}
	return nil
}

func testAudNotOk(pk string, val *Validator, iss string) error {
	userIn := "abc_123"
	token := createToken(pk, jwt.MapClaims{
		"iss": iss,
		"aud": "notvalid",
		"sub": userIn,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := val.Validate(token)
	if err == nil {
		return fmt.Errorf("did not receive the expected error")
	}
	return nil
}

func testOtherKey(val *Validator, iss string, aud string) error {
	privKey := GenPrivateKey()
	userIn := "abc_123"
	token := createToken(privKey, jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": userIn,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := val.Validate(token)
	if err == nil {
		return fmt.Errorf("did not receive expected error")
	}
	return nil
}

func testExpired(pk string, val *Validator, iss string, aud string) error {
	userIn := "abc_123"
	exp := (time.Now().Unix()) - 1
	token := createToken(pk, jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": userIn,
		"exp": exp,
	})

	_, err := val.Validate(token)
	if err == nil {
		return fmt.Errorf("did not received expected err")
	}
	return nil
}

func TestBadValidator(t *testing.T) {
	_, pubKey := genKeys()

	_, err := NewValidator("notvalid", "MyIss", "MyAud")
	if err == nil {
		t.Error("publicKey: did not receive expected error")
	}
	_, err = NewValidator("$", "MyIss", "MyAud")
	if err == nil {
		t.Error("$publicKey: did not receive expected error")
	}
	_, err = NewValidator("", "MyIss", "MyAud")
	if err == nil {
		t.Error("empty publicKey: did not receive expected error")
	}
	_, err = NewValidator(pubKey, "", "MyAud")
	if err == nil {
		t.Error("iss: did not receive expected error")
	}
	_, err = NewValidator(pubKey, "MyIss", "")
	if err == nil {
		t.Error("aud: did not receive expected error")
	}
}
