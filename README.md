# jwtrsa

jwtrsa is a Go package providing high-level wrappers for issuing and validating JSON Web Tokens (JWT) using RSA (RS256) signatures. It leverages github.com/golang-jwt/jwt/v5 for cryptographic operations and errordetail for structured error reporting.
+1

Features
* **Secure Issuance:** Encapsulates RSA private keys to sign tokens with standard registered claims.
* **Structured Validation:** Pre-configures JWT parsers with strict audience and issuer requirements.
* **Key Management:** Utilities for generating RSA key pairs and converting private keys to public PEM format.
* **Developer Friendly:** Includes a comprehensive Makefile for testing, linting, and security scanning.

## Installation

```bash
go get github.com/johnhealio/jwtrsa
```

## Usage

Issue a token
```Go
issuer, _ := jwtrsa.NewIssuer(privateKeyPem)

claims := map[string]any{
    "iss": "my-trusted-issuer",
    "aud": jwt.ClaimStrings{"my-service"},
    "iat": time.Now().Unix(),
    "exp": time.Now().Add(time.Hour).Unix(),
    "sub": "user-123",
}

token, err := issuer.Issue(claims)
```

Validating a Token
```Go
validator, _ := jwtrsa.NewValidator(publicKeyPem, "my-trusted-issuer", "my-service")

subject, err := validator.Validate(token)
if err == nil {
    fmt.Printf("Authenticated user: %s\n", subject)
}
```

## Development
Use the provided Makefile to maintain code quality:

* **make test:** Run unit tests with race detection.
* **make test-coverage:** View HTML test coverage report.
* **make lint:** Run golangci-lint.
* **make scan:** Check for vulnerabilities using govulncheck.
