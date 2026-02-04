package jwtrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Helpers to generate a real RSA key pair for testing
func generateKeyPair() (privPem string, pubPem string) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	privBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(privBlock), string(pubBlock)
}

// Helper to create a signed token for testing
func createToken(privPem string, claims jwt.MapClaims) string {
	key, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privPem))
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := token.SignedString(key)
	return s
}

func TestValidator_Validate(t *testing.T) {
	priv, pub := generateKeyPair()
	//_, otherPub := generateKeyPair() // For testing wrong signature

	issuer := "trusted-issuer"
	audience := "my-app"

	tests := getIssuerTests(priv, issuer, audience)

	v, err := NewValidator(pub, issuer, audience)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSub, err := v.Validate(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSub != tt.wantSub {
				t.Errorf("Validate() gotSub = %v, want %v", gotSub, tt.wantSub)
			}
		})
	}
}

func TestNewValidator_ConstructorErrors(t *testing.T) {
	t.Run("Empty Public Key", func(t *testing.T) {
		if _, err := NewValidator("", "iss", "aud"); err == nil {
			t.Error("expected error for empty public key")
		}
	})

	t.Run("Invalid PEM Format", func(t *testing.T) {
		if _, err := NewValidator("not-a-pem", "iss", "aud"); err == nil {
			t.Error("expected error for invalid PEM")
		}
	})
}

type testCaseIssuer struct {
	name    string
	token   string
	wantSub string
	wantErr bool
}

func getIssuerTests(priv string, issuer string, audience string) []testCaseIssuer {
	now := time.Now()

	tests := []testCaseIssuer{
		{
			name: "Valid Token",
			token: createToken(priv, jwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": "user_123",
				"exp": now.Add(time.Hour).Unix(),
			}),
			wantSub: "user_123",
			wantErr: false,
		},
		{
			name: "Expired Token",
			token: createToken(priv, jwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": "user_123",
				"exp": now.Add(-time.Hour).Unix(),
			}),
			wantErr: true,
		},
		{
			name: "Wrong Issuer",
			token: createToken(priv, jwt.MapClaims{
				"iss": "malicious-issuer",
				"aud": audience,
				"sub": "user_123",
				"exp": now.Add(time.Hour).Unix(),
			}),
			wantErr: true,
		},
		{
			name: "Wrong Audience",
			token: createToken(priv, jwt.MapClaims{
				"iss": issuer,
				"aud": "wrong-app",
				"sub": "user_123",
				"exp": now.Add(time.Hour).Unix(),
			}),
			wantErr: true,
		},
		{
			name: "Invalid Signature",
			token: func() string {
				otherPriv, _ := generateKeyPair() // Signed with a different key
				return createToken(otherPriv, jwt.MapClaims{
					"iss": issuer, "aud": audience, "sub": "user_123", "exp": now.Add(time.Hour).Unix(),
				})
			}(),
			wantErr: true,
		},
	}
	return tests
}
