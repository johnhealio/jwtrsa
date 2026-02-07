// Package jwtrsa is a Go package providing high-level wrappers for issuing and validating JSON Web Tokens (JWT) using RSA (RS256) signatures.
package jwtrsa

import (
	"crypto/rsa"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
	"github.com/johnhealio/errordetail"
)

// Validator holds the parsed public key and configured parse used to validate a JWT
type Validator struct {
	publicKey *rsa.PublicKey
	parser    *jwt.Parser
}

// NewValidator returns a Validator object
func NewValidator(publicKeyB64 string, trustedIssuer string, audience string) (*Validator, error) {
	if publicKeyB64 == "" {
		return nil, errordetail.New(0, "public key is empty", nil)
	}
	if trustedIssuer == "" {
		return nil, errordetail.New(0, "issuer is empty", nil)
	}
	if audience == "" {
		return nil, errordetail.New(0, "audience is empty", nil)
	}

	bytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, errordetail.New(0, "unable to decode public key", nil)
	}

	parsedPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		return nil, errordetail.New(0, "unable to parse public key", err)
	}

	parser := jwt.NewParser(
		jwt.WithAudience(audience),
		jwt.WithIssuer(trustedIssuer),
		jwt.WithValidMethods([]string{"RS256"}),
	)

	return &Validator{
		publicKey: parsedPublicKey,
		parser:    parser,
	}, nil
}

// Validate the JWT and extracts the sub field
// It returns a detailed error if token is not valid
func (j *Validator) Validate(tokenStr string) (string, error) {
	var claims jwt.RegisteredClaims
	token, err := j.parser.ParseWithClaims(tokenStr, &claims,
		func(_ *jwt.Token) (interface{}, error) {
			return j.publicKey, nil
		})

	if err != nil || !token.Valid {
		return "", errordetail.New(401, "token is not valid", err)
	}

	sub, err := claims.GetSubject()
	if sub == "" || err != nil {
		return "", errordetail.New(401, "subject is empty", err)
	}
	return sub, nil
}
