package jwtrsa

import (
	"crypto/rsa"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
	"github.com/johnhealio/errordetail"
)

// Issuer holds a parsed RSA private key and issues tokens including a given set of claims
type Issuer struct {
	privateKey *rsa.PrivateKey
}

// NewIssuer receives a private key as a string and returns an Issuer object
func NewIssuer(privateKeyPem string) (*Issuer, error) {
	if privateKeyPem == "" {
		return nil, errordetail.New(1, "privateKeyPem is empty", nil)
	}
	privStr, err := base64.StdEncoding.DecodeString(privateKeyPem)
	if err != nil {
		return nil, errordetail.New(1, "unable to decode private key", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privStr))
	if err != nil {
		return nil, errordetail.New(1, "unable to create private key", err)
	}
	return &Issuer{privateKey: privateKey}, nil
}

// Issue returns a token string including the given set of claims
func (j *Issuer) Issue(claimsMap map[string]any) (string, error) {
	if err := j.complete(claimsMap); err != nil {
		return "", err
	}

	claims := jwt.MapClaims(claimsMap)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", errordetail.New(1, "unable to sign token", err)
	}
	return signedToken, nil
}

// complete is used to verify that the claims set includes all the required fields
func (j *Issuer) complete(claimsMap map[string]any) error {
	iss, ok := claimsMap["iss"].(string)
	if !ok || iss == "" {
		return errordetail.New(1, "issuer not found", nil)
	}

	aud, ok := claimsMap["aud"].(jwt.ClaimStrings)
	if !ok || len(aud) == 0 {
		return errordetail.New(0, "audience not found", nil)
	}
	for i := range aud {
		if aud[i] == "" {
			return errordetail.New(1, "empty audience is not allowed", nil)
		}
	}

	iat, ok := claimsMap["iat"].(int64)
	if !ok || iat == 0 {
		return errordetail.New(1, "iat not found", nil)
	}

	exp, ok := claimsMap["exp"].(int64)
	if !ok || exp == 0 {
		return errordetail.New(1, "exp not found", nil)
	}

	sub, ok := claimsMap["sub"].(string)
	if !ok || sub == "" {
		return errordetail.New(1, "subject not found", nil)
	}

	return nil
}
