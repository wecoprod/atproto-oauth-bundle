# Changelog

## 0.1.0 (unreleased)

- First version: confidential atproto OAuth client (PAR, PKCE S256, DPoP with server nonces, private_key_jwt ES256)
- Identity resolution: handle (DNS TXT, HTTPS well-known) → DID (did:plc, did:web) → PDS → authorization server, with bidirectional handle check
- Client metadata and JWKS endpoints, `atproto-oauth:generate-key` command; `client_uri` checked against the `client_id` origin, as authorization servers require
- `SessionManager`: refresh before expiry, serialized with symfony/lock, revocation
- `AtprotoClient`: authenticated XRPC calls (get, post, uploadBlob) with automatic refresh
