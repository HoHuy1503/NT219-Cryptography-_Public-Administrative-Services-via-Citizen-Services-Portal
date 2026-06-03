# GovPortal public/private mTLS deployment

This machine is the private network host. Docker services and Postgres run
locally. The public edge exposes five portal domains on `185.27.134.59`.

## Public domains

- `citizens.gt.tc` -> `citizen.html`, account + phone OTP flow
- `dbadmin.gt.tc` -> `storage.html`, browser client certificate required
- `thirdparties.gt.tc` -> `thirdparty.html`, browser client certificate required
- `pki.gt.tc` -> `pki.html`, browser client certificate required
- `officers.gt.tc` -> `officer.html`, browser client certificate required

The portal JavaScript calls same-origin `/api/...` on public domains. The edge
nginx proxies `/api/` to the local gateway at `127.0.0.1:8080`.

## Generate internal ML-DSA-44 service certificates

```bash
cd DEPLOY/D2
bash scripts/generate_mldsa_mtls_certs.sh
```

Important: the stock `nginx:alpine` containers may not load ML-DSA-44 TLS
certificates. Rebuild gateway and service nginx against OpenSSL 3.6.1 before
using these certificates for live TLS/mTLS. If nginx cannot start with these
certificates, keep ECDSA for TLS transport and use ML-DSA for document/officer
PKI until the TLS stack supports it.

## Generate browser/USB-token client certificates

```bash
cd DEPLOY/D2
PFX_PASSWORD='change-me' bash scripts/generate_portal_client_certs.sh
```

Outputs are under:

```text
domain_key/browser_clients/ca/portal-client-ca.crt
domain_key/browser_clients/pfx/pki_admin.p12
domain_key/browser_clients/pfx/thirdparty.p12
domain_key/browser_clients/pfx/officer.p12
domain_key/browser_clients/pfx/storage_admin.p12
```

Install `portal-client-ca.crt` as the trusted client CA in public nginx. Import
the `.p12` files into the browser/OS certificate store or a hardware token.

## Install public nginx config

Create a fullchain for the public ZeroSSL certificate. The certificate must
cover the public portal hostnames, either `*.gt.tc` or the exact SANs
`citizens.gt.tc`, `dbadmin.gt.tc`, `thirdparties.gt.tc`, `pki.gt.tc`, and
`officers.gt.tc`.

```powershell
Get-Content "domain_key\certificate.crt", "domain_key\ca_bundle.crt" | Set-Content "domain_key\fullchain.crt"
```

Use `DEPLOY/D2/nginx-public/govportal-public.conf` as the template. Replace:

- `PORTAL_ROOT` with the absolute path to `DEPLOY/D2/portals`
- `DOMAIN_CERT_FULLCHAIN` with the fullchain path
- `DOMAIN_CERT_KEY` with the matching domain private key
- `CLIENT_CA` with `domain_key/browser_clients/ca/portal-client-ca.crt`

Then load/reload nginx.

## USB token flow

For a real USB smart card/token, import the `.p12` into the token using the
vendor tool or a PKCS#11 tool. The browser does not receive the private key in
JavaScript. During TLS handshake, the browser asks the OS/token for a client
certificate; the user selects it and enters the token PIN. Nginx verifies it
against `portal-client-ca.crt` before allowing the portal/API request.
