# Kien Truc GovPortal PKI

## 1. Muc Tieu

GovPortal la he thong demo cong dich vu voi 5 portal public:

| Portal | Domain | Dang nhap |
| --- | --- | --- |
| Citizen | `citizens.hnh2511.xyz` | Tai khoan va OTP/SMS theo luong ung dung |
| Storage Admin | `dbadmin.hnh2511.xyz` | Client certificate tren trinh duyet |
| Third Party | `thirdparties.hnh2511.xyz` | Client certificate tren trinh duyet |
| PKI Admin | `pki.hnh2511.xyz` | Client certificate tren trinh duyet |
| Officer | `officers.hnh2511.xyz` | Client certificate tren trinh duyet |

Citizen la portal public cho nguoi dan. Bon portal con lai la portal co kiem tra client certificate o lop TLS. API noi bo giua gateway va services cung di qua mTLS.

## 2. Tong Quan Luong Mang

```text
Internet
  |
  | HTTPS public, Let's Encrypt cert
  v
Host Nginx tren Azure VM
  |
  | static portal files + /api reverse proxy
  v
Docker gateway Nginx, localhost:8080
  |
  | auth_request sang authz_proxy/OPA
  | mTLS toi services noi bo
  v
storage_service, doc_service, qr_service, postgres
```

Public IP hien tai: `20.205.109.23`.

Public TLS certificate dang dung:

```text
/etc/letsencrypt/live/citizens.hnh2511.xyz/fullchain.pem
/etc/letsencrypt/live/citizens.hnh2511.xyz/privkey.pem
```

Certificate nay co SAN cho 5 subdomain.

## 3. Docker Compose

File chinh: `DEPLOY/D2/docker-compose.yml`.

Services:

| Service | Vai tro |
| --- | --- |
| `postgres` | Database chinh, database name `docdb` |
| `opa` | Policy engine, doc policy nam trong `docker/opa/policies` |
| `authz_proxy` | Doc JWT, tao input cho OPA, tra allow/deny cho gateway |
| `storage_service` | Tai khoan, documents, requests, cert metadata, audit log |
| `doc_service` | PKI/CA, cap cert, verify chu ky tai lieu |
| `qr_service` | Service QR noi bo |
| `portals` | Server file tinh cho 5 portal va helper local `__keypair`, `__sign` |
| `gateway` | Nginx API gateway noi bo |

Network:

| Network | Muc dich |
| --- | --- |
| `internal` | DB, OPA, authz, services, gateway noi bo |
| `public` | Gateway va portal helper localhost |

Ports chi bind localhost:

```text
127.0.0.1:3000-3004 -> portal helper
127.0.0.1:8080      -> gateway HTTP
127.0.0.1:8443      -> gateway HTTPS noi bo
```

Vi chi bind `127.0.0.1`, nguoi ngoai khong vao truc tiep Docker duoc. Public traffic phai di qua host Nginx tren port 80/443.

Volumes quan trong:

```text
DEPLOY/D2/state              -> state runtime
DEPLOY/D2/state/mtls         -> cert mTLS noi bo cho service
/home/hnh/Documents/openssl/openssl-3.6.1 -> OpenSSL 3.6.1 build san
```

## 4. Host Nginx Public

File tren server:

```text
/etc/nginx/sites-available/govportal
/etc/nginx/sites-enabled/govportal
```

Vai tro:

- Terminate HTTPS public bang cert Let's Encrypt.
- Redirect HTTP port 80 sang HTTPS.
- Serve file portal HTML/CSS/JS tu `/opt/govportal/DEPLOY/D2/portals`.
- Proxy `/api/` ve Docker gateway `http://127.0.0.1:8080`.
- Bat client certificate cho:
  - `dbadmin.hnh2511.xyz`
  - `thirdparties.hnh2511.xyz`
  - `pki.hnh2511.xyz`
  - `officers.hnh2511.xyz`
- Khong bat client certificate cho `citizens.hnh2511.xyz`.

Trust bundle cho client certificate:

```text
/etc/nginx/govportal/client-ca-bundle.crt
```

Bundle nay gom CA client cu va CA PKI moi neu da co.

Host Nginx cung proxy helper:

| Route | Dung cho |
| --- | --- |
| `/__keypair` tren officer/thirdparty | Tao keypair phia portal helper |
| `/__sign` tren officer | Ky tai lieu bang private key local cua officer |

## 5. Nginx Gateway Trong Docker

File chinh:

```text
DEPLOY/D2/docker/gateway/nginx.conf
```

Vai tro:

- Nhan API tu host Nginx.
- Xu ly CORS cho dev portal ports `3000-3004`.
- Goi `authz_proxy` qua `auth_request /_opa_auth`.
- Route request toi storage/doc/qr services.
- Ket noi toi services bang mTLS noi bo.

Include files:

| File | Vai tro |
| --- | --- |
| `proxy_storage_public.conf` | Public API khong can JWT nhu login/register/JWKS |
| `proxy_storage_protected.conf` | Protected storage APIs, can OPA allow |
| `proxy_other.conf` | Route `/api/pki`, `/api/qr`, `/doc`, `/health` |
| `proxy_mtls_storage.conf` | Cert client gateway khi goi storage service |
| `proxy_mtls_doc.conf` | Cert client gateway khi goi doc service |
| `proxy_mtls_qr.conf` | Cert client gateway khi goi qr service |
| `proxy_hide_cors.conf` | An CORS headers tu upstream de gateway la nguon CORS duy nhat |

## 6. CORS

CORS duoc dat o Docker gateway Nginx:

```nginx
map $http_origin $cors_origin {
  default "";
  "~^https?://[^/]+:300[0-4]$" $http_origin;
}
```

Muc dich:

- Cho phep dev portal local ports `3000-3004`.
- Tra headers `Access-Control-Allow-*`.
- Tra `204` cho preflight `OPTIONS`.
- An CORS headers tu Flask upstream bang `proxy_hide_header`, tranh loi multiple CORS headers.

Khi chay public domain cung host voi API, frontend goi same-origin `/api`, nen CORS gan nhu khong can tren public path.

## 7. OPA Policy

File:

```text
DEPLOY/D2/docker/opa/policies/authz.rego
```

Nguyen tac:

- Mac dinh `allow = false`.
- Public paths gom health, JWKS, login, register.
- `storage_admin` duoc quan ly hau het storage, tru mot so vung bi chan.
- `pki_admin` duoc duyet request/cap cert, nhung khong vao DB admin destructive endpoint.
- `officer` duoc xem officers, document sign requests, documents, cert requests, identity certs.
- `citizen` duoc xem documents cua minh, tao verify/sign requests, verify QR.
- `thirdparty` duoc xem verify requests, verify QR, lay identity cert cua minh.

Gateway tao request noi bo toi `authz_proxy`; `authz_proxy` doc JWT, tao input gom path/method/user_type, roi hoi OPA.

## 8. Cac Loai Key Va Cert

### 8.1 Public HTTPS certificate

Dung de trinh duyet thay 5 domain la HTTPS hop le.

Server path:

```text
/etc/letsencrypt/live/citizens.hnh2511.xyz/fullchain.pem
/etc/letsencrypt/live/citizens.hnh2511.xyz/privkey.pem
```

Local sync path:

```text
domain_key/letsencrypt/live/citizens.hnh2511.xyz/
```

Cap boi Let's Encrypt, tu dong renew bang Certbot.

### 8.2 Browser client certificate cho mTLS

Dung de dang nhap cac portal noi bo qua browser client certificate.

Local/server path hien co:

```text
domain_key/browser_clients/ca/portal-client-ca.crt
domain_key/browser_clients/ca/portal-client-ca.key
domain_key/browser_clients/pfx/pki_admin.p12
domain_key/browser_clients/pfx/officer.p12
domain_key/browser_clients/pfx/thirdparty.p12
domain_key/browser_clients/pfx/storage_admin.p12
```

`*.p12` co the import vao Windows/browser hoac USB token. Mat khau demo hien tai: `changeit`.

### 8.3 PKI identity certificate moi

Luong moi:

- Officer va thirdparty tao key truy cap rieng.
- Gui public key len PKI.
- PKI admin duyet.
- CA cap client certificate.
- User tai cert mot lan.

Private key nen nam phia client hoac USB token. Server chi nhan public key, nen server khong the tao file `.p12` day du neu khong co private key.

### 8.4 Officer business signing key

Chi officer moi co key ky nghiep vu de ky tai lieu.

Luu trong DB:

```text
officer_keys.public_key_pem
```

Private key khong luu DB; portal/helper giu local de ky.

### 8.5 Internal service mTLS certs

Dung cho gateway goi services noi bo:

```text
DEPLOY/D2/state/mtls/ca/ca.crt
DEPLOY/D2/state/mtls/gateway/client.crt
DEPLOY/D2/state/mtls/gateway/client.key
DEPLOY/D2/state/mtls/services/storage.crt
DEPLOY/D2/state/mtls/services/storage.key
DEPLOY/D2/state/mtls/services/doc.crt
DEPLOY/D2/state/mtls/services/doc.key
DEPLOY/D2/state/mtls/services/qr.crt
DEPLOY/D2/state/mtls/services/qr.key
```

Sinh bang script:

```text
DEPLOY/D2/scripts/generate_mtls_certs.sh
```

### 8.6 CA / PKI state

Runtime path:

```text
DEPLOY/D2/state/pki/ca_key.pem
DEPLOY/D2/state/pki/ca_cert.pem
DEPLOY/D2/state/pki/issued_certs.json
```

`ca_key.pem` la private key CA, phai bao ve. `ca_cert.pem` la public CA certificate, co the dua vao trust bundle.

## 9. Database Chinh

Bang identity:

| Bang | Muc dich |
| --- | --- |
| `citizens` | Tai khoan cong dan |
| `officers` | Tai khoan can bo |
| `thirdparty_users` | Tai khoan to chuc ben thu ba |
| `storage_admins` | Tai khoan quan tri storage |
| `pki_admins` | Tai khoan quan tri PKI |

Bang certificate/key:

| Bang | Muc dich |
| --- | --- |
| `identity_cert_requests` | Request cap cert truy cap cho officer/thirdparty |
| `identity_certificates` | Cert da cap, co co `p12_downloaded_at` de chi tai mot lan |
| `officer_keys` | Public key ky nghiep vu cua officer |
| `officer_certificates` | Bang legacy/compat cho cert active cua officer |

Bang tai lieu:

| Bang | Muc dich |
| --- | --- |
| `documents` | Metadata tai lieu, `content_hash`, status |
| `signatures` | Chu ky, signer, key version |
| `document_qr` | QR token hash, document id, content hash, signature hash |
| `document_sign_requests` | Citizen yeu cau officer ky |
| `document_verify_requests` | Citizen yeu cau thirdparty xac thuc |
| `audit_log` | Audit trail |

## 10. QR Verification

QR payload:

```text
GVP1.<qr_id>.<random_token>
```

Y nghia:

- `GVP1`: version cua QR format.
- `qr_id`: id ban ghi QR.
- `random_token`: token ngau nhien chi nam tren QR.

Trong DB khong luu token goc, chi luu:

```text
token_hash = SHA256(random_token)
content_hash = SHA256(document_bytes)
sig_hash = SHA256(signature_envelope)
```

Khi thirdparty quet:

1. Backend tach `qr_id` va token.
2. Hash token roi doi chieu voi `document_qr.token_hash`.
3. Neu co file tai lieu, backend tinh hash file va so voi `content_hash`.
4. Backend lay signature/public key dung version de verify.
5. Ket qua duoc ghi vao `document_verify_requests`.

Ly do khong nhet signature/document hash vao QR:

- QR ngan hon, de quet hon.
- Khong lo thong tin tai lieu hoac chu ky ra ngoai.
- Co the revoke/rotate QR tren server.
- DB co the xac thuc ma khong can QR chua du lieu lon.

## 11. Script Quan Tri

| Script | Muc dich |
| --- | --- |
| `generate_mtls_certs.sh` | Tao cert mTLS noi bo service |
| `generate_portal_client_certs.ps1/sh` | Tao cert browser client demo |
| `request_letsencrypt_5domains.ps1` | Xin cert public 5 domain bang Certbot/Docker |
| `sync_server_certs.ps1` | Dong bo cert/key can backup tu Azure ve `domain_key` local |

Dong bo tu server ve may chinh:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\Admin\Documents\Mật mã học\DEPLOY\D2\scripts\sync_server_certs.ps1"
```

## 12. Nguyen Tac Bao Mat

- Public HTTPS key nam trong `/etc/letsencrypt`, khong copy len git.
- CA private key chi de trong state/server, khong dua vao frontend.
- Private key truy cap nen nam trong USB token neu trien khai that.
- Officer signing private key khong luu database.
- QR chi chua token ngau nhien, khong chua tai lieu, khong chua chu ky day du.
- Docker services khong expose public port; host Nginx la public edge duy nhat.
