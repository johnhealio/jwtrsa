package jwtrsa

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssuer_Issue(t *testing.T) {
	privateKeyPem := GenPrivateKey()
	issuer, err := NewIssuer(privateKeyPem)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	tests := getTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := issuer.Issue(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("Issue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && token == "" {
				t.Error("Issue() returned empty token on success")
			}
		})
	}
}

func TestInvalidPrivKey(t *testing.T) {
	emptyPrivateKeyPem := ""
	_, err := NewIssuer(emptyPrivateKeyPem)
	if err == nil {
		t.Error("did not receive expected eror")
	}

	invalidPrivateKeyPem := "not valid key"
	_, err = NewIssuer(invalidPrivateKeyPem)
	if err == nil {
		t.Error("did not receive expected eror")
	}
}

type testCase struct {
	name    string
	claims  map[string]any
	wantErr bool
}

func getTests() []testCase {
	now := time.Now().Unix()

	return []testCase{
		{
			name: "Successful Token Issue",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service"}, // Must be jwt.ClaimStrings
				"iat": now,
				"exp": now + 3600,
				"sub": "user-123",
			},
			wantErr: false,
		},
		{
			name: "Failure - Wrong Audience Type",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": []string{"ledger-service"}, // This will fail assertion to jwt.ClaimStrings
				"iat": now,
				"exp": now + 3600,
				"sub": "user-123",
			},
			wantErr: true,
		},
		{
			name: "Failure - Missing Subject",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service"},
				"iat": now,
				"exp": now + 3600,
			},
			wantErr: true,
		},
		{
			name: "Failure - IAT as Float (JSON Style)",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service"},
				"iat": float64(now), // Common when unmarshaling JSON
				"exp": now + 3600,
				"sub": "user-123",
			},
			wantErr: true, // Assertion to int64 will fail
		},
		{
			name: "Failure - empty iss",
			claims: map[string]any{
				"iss": "",
				"aud": jwt.ClaimStrings{"ledger-service"},
				"iat": now,
				"exp": now + 3600,
				"sub": "user-123",
			},
			wantErr: true, // Assertion to int64 will fail
		},
		{
			name: "Failure - empty aud",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service", ""},
				"iat": now,
				"exp": now + 3600,
				"sub": "user-123",
			},
			wantErr: true, // Assertion to int64 will fail
		},
		{
			name: "Failure - exp == 0",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service"},
				"iat": now,
				"exp": 0,
				"sub": "user-123",
			},
			wantErr: true, // Assertion to int64 will fail
		},
		{
			name: "Failure - iat == 0",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service"},
				"iat": 0,
				"exp": now + 3600,
				"sub": "user-123",
			},
			wantErr: true, // Assertion to int64 will fail
		},
		{
			name: "Failure - no sub",
			claims: map[string]any{
				"iss": "test-issuer",
				"aud": jwt.ClaimStrings{"ledger-service"},
				"iat": now,
				"exp": now + 3600,
			},
			wantErr: true, // Assertion to int64 will fail
		},
	}
}
