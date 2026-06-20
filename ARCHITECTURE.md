# GovPortal PKI Architecture

Tai lieu nay tom tat nhung thanh phan dang dung trong repo, chuc nang cua tung phan, topology he thong, va cac loai key/cert quan trong.

## 1. Muc tieu he thong

GovPortal la he thong demo cong dich vu va PKI voi 5 portal public:

| Portal | Domain | Vai tro |
| --- | --- | --- |
| Citizen | `citizens.hnh2511.xyz` | Cong dan dang nhap bang account/OTP, tao yeu cau ky/xac thuc tai lieu |
| Storage Admin | `dbadmin.hnh2511.xyz` | Quan tri database, tai lieu, nguoi dung, audit |
| Third Party | `thirdparties.hnh2511.xyz` | Ben thu ba xac thuc QR/tai lieu |
| PKI Admin | `pki.hnh2511.xyz` | Duyet yeu cau cap cert va quan ly CA/PKI |
| Officer | `officers.hnh2511.xyz` | Can bo xu ly yeu cau va ky nghiep vu |

Citizen la portal public khong bat browser client cert. Bon portal con lai bat browser client cert o lop TLS.

## 2. Topology tong the

```text
                                      Internet
                                         |
                                         | HTTPS public
                                         | Server cert: Let's Encrypt
                                         v
                         +-------------------------------+
                         | Azure VM public IP             |
                         | 20.205.109.23                  |
                         +-------------------------------+
                                         |
                                         v
              +--------------------------------------------------+
              | Host Nginx                                       |
              | /etc/nginx/sites-available/govportal             |
              |                                                  |
              | - Terminate public HTTPS                         |
              | - Serve portal HTML/CSS/JS                       |
              | - Check browser client cert for 4 private portals |
              | - Proxy /api/ to Docker gateway                  |
              +--------------------------------------------------+
                    |             |              |
                    |             |              |
       static HTML  |             | /api/        |
       portals      |             v              v
                    |     +----------------+  +--------------------------+
                    |     | Docker gateway |  | portals container         |
                    |     | 127.0.0.1:8080 |  | 127.0.0.1:3000-3004      |
                    |     | Nginx API GW   |  | static portal files       |
                    |     +----------------+  +--------------------------+
                    |             |
                    |             | auth_request
                    |             v
                    |     +----------------+
                    |     | authz_proxy    |
                    |     | JWT -> OPA     |
                    |     +----------------+
                    |             |
                    |             v
                    |     +----------------+
                    |     | OPA policy     |
                    |     | authz.rego     |
                    |     +----------------+
                    |
                    | Internal mTLS from gateway to services
                    v
          +------------------+       +------------------+       +----------------+
          | storage_service  |       | doc_service      |       | qr_service     |
          | users/documents  |       | PKI CA, certs    |       | QR verify      |
          | requests/audit   |       | signature verify |       | token format   |
          +------------------+       +------------------+       +----------------+
                    |
                    v
              +------------+
              | postgres   |
              | docdb      |
              +------------+

          +------------------+
          | Encrypted key    |
          | vault metadata   |
          +------------------+
                    ^
                    |
          trusted device downloads
          encrypted blob only
```

## 3. Public network flow

```text
Browser
  -> https://<portal-domain>
  -> Host Nginx on Azure VM
  -> static portal file or /api reverse proxy
  -> Docker gateway Nginx on 127.0.0.1:8080
  -> OPA authorization check if route is protected
  -> internal service over mTLS
  -> postgres if data is needed
```

## 3.1 Business signing with encrypted key vault

```text
Officer browser
  -> mTLS login with EC client cert from USB/browser token
  -> downloads document to trusted device
  -> downloads encrypted ML-DSA key blob only
  -> trusted device derives decrypt key from password + PBKDF2
  -> trusted device decrypts local temporary key and signs document
  -> officer uploads detached signature base64
  -> storage_service verifies signature with stored public key
  -> storage_service stores signature, QR metadata, and audit
```

This is not a non-exportable hardware HSM model. It is an encrypted key-vault model:

- Server stores only encrypted private-key blob, public key, KDF params, cert metadata, signatures, and audit.
- Plaintext ML-DSA private key must never be uploaded to the app server.
- Officer client creates ML-DSA key and CSR locally, uploads CSR + encrypted private-key blob.
- PKI server signs the CSR with the server-side ML-DSA CA private key after pki-admin approval.
- `.p12` packages are only for browser mTLS access, not document signing.
- Trusted device is responsible for decrypting and signing locally.

## 3.2 Detailed business flows

### 3.2.1 Citizen submits a document signing request

```text
Citizen browser
  |
  | 1. Login bang account + OTP
  v
Citizen portal
  |
  | 2. POST /api/storage/document-sign-requests
  |    Body gom: citizen_id, officer_id, document metadata,
  |    document_base64/content_hash
  v
Host Nginx
  |
  | 3. Proxy /api/* vao Docker gateway
  v
Docker gateway
  |
  | 4. Kiem tra route/JWT/OPA neu can
  | 5. Goi storage_service bang internal mTLS
  v
storage_service
  |
  | 6. Validate citizen, officer, document
  | 7. Luu document metadata/content/hash vao DB
  | 8. Tao document_sign_requests.status = pending
  | 9. Ghi audit
  v
postgres
  |
  | 10. Tra request_id ve citizen
  v
Citizen portal
```

Ket qua DB:

```text
documents.doc_id
documents.content_hash
document_sign_requests.request_id
document_sign_requests.citizen_id
document_sign_requests.officer_id
document_sign_requests.status = pending
document_sign_requests.document_base64
audit_log
```

### 3.2.2 Officer signs the citizen request

```text
Officer browser
  |
  | 1. Truy cap officers.hnh2511.xyz
  | 2. Browser xuat trinh EC mTLS cert tu USB/browser token
  v
Host Nginx
  |
  | 3. Verify client cert bang browser-client CA
  | 4. Chi cho vao neu CN khop officers domain
  v
Officer portal
  |
  | 5. Login app bang username/password
  | 6. Backend bind account voi TLS client cert subject
  | 7. GET /api/storage/document-sign-requests?status=pending
  v
storage_service
  |
  | 8. Load pending requests cua officer
  | 9. Tra danh sach ho so can ky
  v
Officer portal
  |
  | 10. Officer tai document ve trusted device
  | 11. Officer tai encrypted signing key blob
  |     GET /api/storage/officers/<officer_id>/encrypted-signing-key/current
  v
Trusted device
  |
  | 12. Nhap password
  | 13. PBKDF2 derive decrypt key
  | 14. Giai ma encrypted_private_key_blob thanh ML-DSA key tam
  | 15. Ky document bang ML-DSA
  | 16. Xoa key tam
  | 17. Xuat detached signature base64
  v
Officer portal
  |
  | 18. POST /api/storage/document-sign-requests/<request_id>/complete
  |     Body chi gom detached signature base64
  v
storage_service
  |
  | 19. Load active signing cert + public key cua officer
  | 20. Goi doc_service verify signature bang internal mTLS
  v
doc_service
  |
  | 21. Verify ML-DSA signature voi public key officer
  v
storage_service
  |
  | 22. Neu hop le: luu signature, tao PKCS7-like envelope
  | 23. Cap nhat document_sign_requests.status = signed
  | 24. Cap nhat documents.status = signed
  | 25. Tao QR payload GVP1.<qr_id>.<random_token>
  | 26. Luu token_hash, sig_hash, content_hash, metadata
  | 27. Ghi audit
  v
postgres
```

Server khong nhan:

```text
private_key_pem
cert_pem tu client
password giai ma key
plaintext ML-DSA private key
```

Server chi nhan:

```text
detached signature base64
request_id
session/JWT
TLS client cert subject do Nginx forward
```

### 3.2.3 Officer requests a business signing certificate

```text
Trusted device cua officer
  |
  | 1. Sinh ML-DSA private key
  | 2. Tao business_signing.csr.pem
  | 3. Tao business_signing_public.pem
  | 4. Ma hoa private key:
  |    password + PBKDF2 -> AES encrypted blob
  v
Officer portal
  |
  | 5. POST /api/storage/officers/<officer_id>/register-key
  |    Gui: csr_pem, public_key_pem,
  |    encrypted_private_key_blob, kdf_params
  v
storage_service
  |
  | 6. Validate officer dang login dung account/cert
  | 7. Validate public key ML-DSA
  | 8. Luu encrypted blob vao officer_keys, is_current = FALSE
  | 9. Luu CSR vao identity_cert_requests, status = PENDING
  v
postgres
  |
  | 10. PKI admin thay request trong pki portal
  v
PKI portal
  |
  | 11. PKI admin dang nhap bang EC mTLS cert pki-admin
  | 12. Bam approve request
  v
storage_service
  |
  | 13. Goi doc_service /api/pki/issue-certificate
  |     Gui CSR + subject metadata
  v
doc_service
  |
  | 14. Lay ML-DSA CA private key tren server
  | 15. Kiem tra public key trong CSR khop public_key_pem
  | 16. Ky CSR thanh signing cert
  v
storage_service
  |
  | 17. Luu cert vao identity_certificates
  | 18. Danh dau officer_keys.is_current = TRUE
  | 19. Cap nhat request = ISSUED
  | 20. Ghi audit
  v
postgres
```

### 3.2.4 Third party verifies a QR

```text
Thirdparty browser
  |
  | 1. Truy cap thirdparties.hnh2511.xyz
  | 2. Browser xuat trinh EC mTLS cert thirdparty
  v
Thirdparty portal
  |
  | 3. Quet QR: GVP1.<qr_id>.<random_token>
  | 4. POST /api/storage/verify-document-qr
  v
storage_service
  |
  | 5. Parse qr_id va random_token
  | 6. Hash random_token
  | 7. Lookup document_qr theo qr_id + token_hash
  | 8. Load document/signature/public key/cert metadata
  | 9. Verify content_hash va sig_hash
  | 10. Goi doc_service verify ML-DSA signature neu can
  v
doc_service
  |
  | 11. Verify signature bang public key officer
  v
storage_service
  |
  | 12. Tra ket qua hop le/khong hop le
  | 13. Tang accessed_count va ghi audit
```

Important public paths:

| Path | Xu ly boi |
| --- | --- |
| `/` | Host Nginx serve portal HTML |
| `/api/*` | Host Nginx proxy to Docker gateway |
| `/__keypair`, `/__local-key`, `/__sign` | Disabled on public deploy; private-key operations do not happen in portal helper |

## 4. Repo inventory

### 4.1 Root files

| Path | Chuc nang |
| --- | --- |
| `ARCHITECTURE.md` | Tai lieu kien truc hien tai |
| `domain_key/` | Backup local cua cert/key public HTTPS, browser client cert, va Nginx config |
| `docker-compose.yml` | Khai bao toan bo Docker services, networks, volumes, ports |
| `state_paths.py` | Helper duong dan state runtime |
| `docker/` | Source cua cac service backend va gateway |
| `portals/` | 5 giao dien HTML va portal helper |
| `scripts/` | Script tao cert, xin HTTPS cert, sync cert tu server ve may chinh |
| `nginx-public/` | Template Nginx public cho host VM |

### 4.2 Thu muc trien khai

| Path | Chuc nang |
| --- | --- |
| `docker-compose.yml` | Khai bao toan bo Docker services, networks, volumes, ports |
| `state_paths.py` | Helper duong dan state runtime |
| `docker/` | Source cua cac service backend va gateway |
| `portals/` | 5 giao dien HTML va portal helper |
| `scripts/` | Script tao cert, xin HTTPS cert, sync cert tu server ve may chinh |
| `nginx-public/` | Template Nginx public cho host VM |

### 4.3 Docker services

| Service/path | Chuc nang |
| --- | --- |
| `docker/storage_service/app.py` | API chinh: login, users, documents, requests, QR metadata, cert request metadata, audit |
| `docker/storage_service/jwt_auth.py` | Tao/verify JWT va JWKS |
| `docker/storage_service/nginx-internal.conf` | Nginx noi bo cua storage service, bat mTLS |
| `docker/doc_service/app.py` | PKI CA, cap cert, verify chu ky/tai lieu |
| `docker/doc_service/nginx-internal.conf` | Nginx noi bo cua doc service, bat mTLS |
| `docker/qr_service/app.py` | Xu ly QR verify noi bo |
| `docker/qr_service/nginx-internal.conf` | Nginx noi bo cua QR service, bat mTLS |
| `docker/authz_proxy/app.py` | Doc JWT, tao input cho OPA, tra allow/deny cho gateway |
| `docker/opa/policies/authz.rego` | Policy phan quyen tap trung |
| `docker/gateway/nginx.conf` | API gateway Nginx trong Docker |
| `docker/gateway/conf.d/*.conf` | Route API, CORS cleanup, va cau hinh mTLS khi gateway goi services |

### 4.4 Portal files

| File | Chuc nang |
| --- | --- |
| `portals/citizen.html` | Giao dien cong dan |
| `portals/storage.html` | Giao dien storage admin |
| `portals/thirdparty.html` | Giao dien ben thu ba |
| `portals/pki.html` | Giao dien PKI admin |
| `portals/officer.html` | Giao dien officer |
| `portals/portal-api.js` | Helper frontend de goi API theo same-origin/public-local mode |
| `portals/shared-portal.css` | CSS dung chung |
| `portals/start_portals.py` | Static file server. Private-key helper endpoints bi tat |

### 4.5 Scripts

| Script | Chuc nang |
| --- | --- |
| `scripts/sync_server_certs.ps1` | Dong bo cert/key quan trong tu Azure VM ve `domain_key/` local |
| `scripts/generate_initial_p12.ps1` | Tao p12 mTLS ban dau cho officer/thirdparty tu CA browser-client |
| `scripts/generate_client_key_material.ps1` | Tao key EC mTLS cho USB/browser token |
| `scripts/sign_document_local.ps1` | Ky tai lieu tren trusted device tu encrypted ML-DSA key blob |

## 5. Docker Compose

File chinh:

```text
docker-compose.yml
```

Services:

| Service | Vai tro |
| --- | --- |
| `postgres` | Database chinh, database name `docdb` |
| `opa` | Policy engine |
| `authz_proxy` | Bridge giua gateway va OPA |
| `storage_service` | API nghiep vu va database access |
| `doc_service` | PKI CA, cap cert, verify chu ky tai lieu |
| `qr_service` | QR service noi bo |
| `gateway` | Nginx API gateway |
| `portals` | Static portal server |

Networks:

| Network | Muc dich |
| --- | --- |
| `internal` | DB, OPA, authz, services, gateway noi bo |
| `public` | Gateway va portals container |

Public exposure:

```text
127.0.0.1:3000-3004 -> static portals
127.0.0.1:8080      -> Docker gateway HTTP
127.0.0.1:8443      -> Docker gateway HTTPS internal
```

Vi chi bind localhost, nguoi ngoai chi vao duoc qua Host Nginx.

## 6. Nginx public on Azure VM

Server path:

```text
/etc/nginx/sites-available/govportal
/etc/nginx/sites-enabled/govportal
```

Chuc nang:

- Dung Let's Encrypt cert de terminate HTTPS public.
- Redirect HTTP sang HTTPS.
- Serve 5 portal static files tu `/opt/govportal/portals`.
- Bat browser client cert cho `dbadmin`, `thirdparties`, `pki`, `officers`.
- Khong bat browser client cert cho `citizens`.
- Gioi han dung client cert theo tung portal bang subject DN:
  - `dbadmin` chi nhan cert storage admin.
  - `thirdparties` chi nhan cert third party co subject gan voi tung `thirdparty_id`.
  - `pki` chi nhan cert PKI admin.
  - `officers` chi nhan cert officer co subject gan voi tung `officer_id`.
- Backend login tiep tuc kiem tra subject cert khop account dang dang nhap. Vi du `officer_demo` phai dung cert co `CN=officer_demo@officers.hnh2511.xyz`; cert cua officer khac khong dang nhap duoc vao account nay.
- Proxy `/api/` ve `http://127.0.0.1:8080`.
- Khong proxy helper tao key/ky tai lieu; tao key va ky tai lieu thuc hien o client.

Trust bundle cho browser client cert:

```text
/etc/nginx/govportal/client-ca-bundle.crt
```

## 7. Docker gateway Nginx

File:

```text
docker/gateway/nginx.conf
```

Chuc nang:

- Nhan API tu Host Nginx.
- Dat CORS header.
- Tra `204` cho `OPTIONS`.
- Goi `authz_proxy` bang `auth_request`.
- Route request toi storage/doc/qr.
- Dung client cert cua gateway de goi services qua mTLS.

Include files:

| File | Chuc nang |
| --- | --- |
| `proxy_storage_public.conf` | API public: login, register, health/JWKS neu co |
| `proxy_storage_protected.conf` | API storage can JWT/OPA |
| `proxy_other.conf` | Route PKI, QR, doc, health |
| `proxy_mtls_storage.conf` | Cert gateway khi goi storage |
| `proxy_mtls_doc.conf` | Cert gateway khi goi doc |
| `proxy_mtls_qr.conf` | Cert gateway khi goi QR |
| `proxy_hide_cors.conf` | Xoa CORS header tu upstream de gateway la noi duy nhat set CORS |

## 8. OPA and authorization

Policy file:

```text
docker/opa/policies/authz.rego
```

Auth flow:

```text
Gateway
  -> auth_request /_opa_auth
  -> authz_proxy
  -> decode JWT
  -> build input {method, path, user_type, user_id}
  -> OPA /v1/data/govportal/authz/allow
  -> allow or deny
```

Nguyen tac:

- Mac dinh deny.
- Public route duoc khai bao ro.
- Route protected phai co JWT hop le.
- Quyen tach theo role: citizen, officer, thirdparty, pki_admin, storage_admin.

## 9. CORS

CORS duoc dat tai Docker gateway, khong dat rai rac o tung Flask service.

Muc dich:

- Cho portal dev ports `3000-3004` goi API.
- Cho phep credential/header can thiet.
- Xu ly preflight `OPTIONS`.
- Tranh loi duplicate CORS header bang `proxy_hide_cors.conf`.

Khi chay tren public domain, frontend goi same-origin `/api`, nen CORS it quan trong hon nhung van giu de dev/test.

## 10. Key and certificate inventory

### 10.1 Public HTTPS cert

Owner: Azure VM / public Host Nginx.

Dung de browser tin 5 domain public.

Server path:

```text
/etc/letsencrypt/live/citizens.hnh2511.xyz/fullchain.pem
/etc/letsencrypt/live/citizens.hnh2511.xyz/privkey.pem
```

Local backup:

```text
domain_key/letsencrypt/live/citizens.hnh2511.xyz/
```

`fullchain.pem` la cert public + chain. `privkey.pem` la private key cua domain, phai giu kin.

### 10.2 Browser client cert

Owner: pki_admin, officer, thirdparty, storage_admin.

Dung de login vao cac portal bat mTLS.

Local path:

```text
domain_key/browser_clients/ca/portal-client-ca.crt
domain_key/browser_clients/ca/portal-client-ca.key
domain_key/browser_clients/pfx/pki_admin.p12
domain_key/browser_clients/pfx/officer.p12
domain_key/browser_clients/pfx/thirdparty.p12
domain_key/browser_clients/pfx/storage_admin.p12
```

`*.p12` chua private key + client cert, dung de import vao Windows/browser/USB token. `portal-client-ca.key` la CA private key de ky client cert demo, can bao ve.

### 10.3 Internal service mTLS cert

Owner: gateway va internal services.

Dung de gateway goi storage/doc/qr qua mTLS.

Runtime path:

```text
state/mtls/ca/ca.crt
state/mtls/gateway/client.crt
state/mtls/gateway/client.key
state/mtls/services/storage.crt
state/mtls/services/storage.key
state/mtls/services/doc.crt
state/mtls/services/doc.key
state/mtls/services/qr.crt
state/mtls/services/qr.key
```

Docker mount:

```text
./state/mtls:/etc/nginx/mtls:ro
```

### 10.4 PKI CA cert/key

Owner: PKI/CA service.

Dung de cap cert cho officer/thirdparty theo luong request/approve/download.

Runtime path:

```text
state/pki/ca_key.pem
state/pki/ca_cert.pem
state/pki/issued_certs.json
```

`ca_key.pem` la private key CA, can bao ve cao nhat. `ca_cert.pem` la public CA cert.

### 10.5 Officer business signing key

Owner: officer.

Dung de ky nghiep vu/tai lieu. Day la key khac voi key mTLS dang nhap.

DB chi luu public key va metadata:

```text
officer_keys.public_key_pem
officer_keys.key_version
officer_keys.encrypted_private_key_blob
officer_keys.encrypted_private_key_format
officer_keys.kdf_params
officer_keys.key_storage_mode
```

DB chi luu private key o dang da ma hoa. Password khong luu DB. Khi ky, trusted device tai blob ma hoa, dung password + PBKDF2 de giai ma cuc bo, ky tai lieu, xoa key tam, roi upload detached signature base64. `.p12` hien tai la goi mTLS de trinh duyet xuat trinh khi vao portal, khong phai key ky tai lieu. Key EC mTLS nam tren USB/browser token theo luong cu.

CSR luong cap cert signing:

```text
trusted device sinh ML-DSA key
  -> tao business_signing.csr.pem
  -> ma hoa private key thanh business_signing_private.pem.enc.b64
  -> POST CSR + encrypted blob len storage
  -> PKI admin duyet
  -> doc_service dung ML-DSA CA private key tren server de ky CSR
  -> storage luu cert va danh dau key current
```

## 11. Certbot role

Certbot chi dung cho public HTTPS cert cua domain.

No khong phai CA noi bo. No khong cap cert officer, thirdparty, USB token, hay service mesh.

Certbot lam:

```text
1. Chung minh domain thuoc quyen kiem soat cua server
2. Xin cert tu Let's Encrypt
3. Luu cert/key vao /etc/letsencrypt
4. Gia han cert khi gan het han
```

## 12. Database summary

| Bang | Muc dich |
| --- | --- |
| `citizens` | Tai khoan cong dan |
| `officers` | Tai khoan can bo |
| `thirdparty_users` | Tai khoan ben thu ba |
| `storage_admins` | Tai khoan storage admin |
| `pki_admins` | Tai khoan PKI admin |
| `documents` | Metadata tai lieu va hash noi dung |
| `signatures` | Chu ky tai lieu va signer |
| `document_qr` | QR id, token hash, document/signature hash |
| `document_sign_requests` | Yeu cau cong dan gui officer ky |
| `document_verify_requests` | Yeu cau cong dan gui thirdparty xac thuc |
| `identity_cert_requests` | Yeu cau cap cert truy cap |
| `identity_certificates` | Cert da cap, chi cho tai mot lan |
| `officer_keys` | Public key ky nghiep vu, encrypted key blob, KDF metadata |
| `audit_log` | Lich su hanh dong |

## 13. QR topology

```text
Citizen/Officer action
  -> document stored/hashed
  -> QR record created
  -> QR payload = GVP1.<qr_id>.<random_token>
  -> database stores token_hash, content_hash, sig_hash

Thirdparty scan
  -> send QR payload to API
  -> backend hashes token
  -> lookup qr_id + token_hash
  -> verify document hash and signature metadata
  -> return verification result
```

Ly do QR chi chua id + random token:

- QR ngan va de quet.
- Khong dua document/signature day du ra ngoai.
- Co the revoke/rotate QR tren server.
- DB chi luu token hash, khong luu token goc.

## 14. Security principles

- Public edge duy nhat la Host Nginx port 80/443.
- Docker services khong expose public port.
- 4 private portals bi chan bang browser client cert truoc khi vao app.
- API protected phai qua JWT va OPA.
- Gateway goi service bang mTLS.
- Private key plaintext khong dua vao frontend/app server; trusted device chi upload detached signature.
- CA private key va domain private key khong nen commit len git.
- USB token giu key EC mTLS. Key ML-DSA nghiep vu trong repo nay la encrypted key-vault model; neu can non-exportable that thi dung HSM/PKCS#11 chuyen dung.
