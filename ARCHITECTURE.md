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
       static HTML  |             | /api/        | helper routes
       portals      |             v              v
                    |     +----------------+  +--------------------------+
                    |     | Docker gateway |  | portals container         |
                    |     | 127.0.0.1:8080 |  | 127.0.0.1:3000-3004      |
                    |     | Nginx API GW   |  | __keypair / __sign helper |
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
          | users/documents  |       | PKI/CA, certs    |       | QR verify      |
          | requests/audit   |       | document verify  |       | token format   |
          +------------------+       +------------------+       +----------------+
                    |
                    v
              +------------+
              | postgres   |
              | docdb      |
              +------------+
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

Important public paths:

| Path | Xu ly boi |
| --- | --- |
| `/` | Host Nginx serve portal HTML |
| `/api/*` | Host Nginx proxy to Docker gateway |
| `/__keypair` | Host Nginx proxy to portals helper for officer/thirdparty |
| `/__sign` | Host Nginx proxy to portals helper for officer |

## 4. Repo inventory

### 4.1 Root files

| Path | Chuc nang |
| --- | --- |
| `ARCHITECTURE.md` | Tai lieu kien truc hien tai |
| `domain_key/` | Backup local cua cert/key public HTTPS, browser client cert, va Nginx config |
| `DEPLOY/D2/` | Stack deploy chinh cua he thong |

### 4.2 DEPLOY/D2

| Path | Chuc nang |
| --- | --- |
| `DEPLOY/D2/docker-compose.yml` | Khai bao toan bo Docker services, networks, volumes, ports |
| `DEPLOY/D2/state_paths.py` | Helper duong dan state runtime |
| `DEPLOY/D2/docker/` | Source cua cac service backend va gateway |
| `DEPLOY/D2/portals/` | 5 giao dien HTML va portal helper |
| `DEPLOY/D2/scripts/` | Script tao cert, xin HTTPS cert, sync cert tu server ve may chinh |
| `DEPLOY/D2/nginx-public/` | Template Nginx public cho host VM |

### 4.3 Docker services

| Service/path | Chuc nang |
| --- | --- |
| `docker/storage_service/app.py` | API chinh: login, users, documents, requests, QR metadata, cert request metadata, audit |
| `docker/storage_service/jwt_auth.py` | Tao/verify JWT va JWKS |
| `docker/storage_service/nginx-internal.conf` | Nginx noi bo cua storage service, bat mTLS |
| `docker/doc_service/app.py` | PKI/CA, cap cert, verify chu ky/tai lieu |
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
| `portals/start_portals.py` | Static file server va helper local `__keypair`, `__sign` |

### 4.5 Scripts

| Script | Chuc nang |
| --- | --- |
| `scripts/generate_mtls_certs.sh` | Tao cert mTLS noi bo cho gateway/services |
| `scripts/generate_mldsa_mtls_certs.ps1/sh` | Script thu nghiem tao cert noi bo bang OpenSSL moi |
| `scripts/generate_portal_client_certs.ps1/sh` | Tao browser client cert demo cho pki/officer/thirdparty/storage_admin |
| `scripts/request_letsencrypt_5domains.ps1` | Xin cert Let's Encrypt cho 5 domain bang Certbot/Docker |
| `scripts/request_letsencrypt_wildcard.ps1` | Xin wildcard cert Let's Encrypt bang DNS challenge |
| `scripts/sync_server_certs.ps1` | Dong bo cert/key quan trong tu Azure VM ve `domain_key/` local |

## 5. Docker Compose

File chinh:

```text
DEPLOY/D2/docker-compose.yml
```

Services:

| Service | Vai tro |
| --- | --- |
| `postgres` | Database chinh, database name `docdb` |
| `opa` | Policy engine |
| `authz_proxy` | Bridge giua gateway va OPA |
| `storage_service` | API nghiep vu va database access |
| `doc_service` | PKI/CA va verify tai lieu |
| `qr_service` | QR service noi bo |
| `gateway` | Nginx API gateway |
| `portals` | Static portal server va helper local |

Networks:

| Network | Muc dich |
| --- | --- |
| `internal` | DB, OPA, authz, services, gateway noi bo |
| `public` | Gateway va portals container |

Public exposure:

```text
127.0.0.1:3000-3004 -> portals/helper
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
- Serve 5 portal static files tu `/opt/govportal/DEPLOY/D2/portals`.
- Bat browser client cert cho `dbadmin`, `thirdparties`, `pki`, `officers`.
- Khong bat browser client cert cho `citizens`.
- Gioi han dung client cert theo tung portal bang subject DN:
  - `dbadmin` chi nhan cert storage admin.
  - `thirdparties` chi nhan cert third party co subject gan voi tung `thirdparty_id`.
  - `pki` chi nhan cert PKI admin.
  - `officers` chi nhan cert officer co subject gan voi tung `officer_id`.
- Backend login tiep tuc kiem tra subject cert khop account dang dang nhap. Vi du `officer_demo` phai dung cert co `CN=officer_demo@officers.hnh2511.xyz`; cert cua officer khac khong dang nhap duoc vao account nay.
- Proxy `/api/` ve `http://127.0.0.1:8080`.
- Proxy helper route cho officer/thirdparty khi can tao key hoac ky.

Trust bundle cho browser client cert:

```text
/etc/nginx/govportal/client-ca-bundle.crt
```

## 7. Docker gateway Nginx

File:

```text
DEPLOY/D2/docker/gateway/nginx.conf
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
DEPLOY/D2/docker/opa/policies/authz.rego
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

Docker mount:

```text
./state/mtls:/etc/nginx/mtls:ro
```

### 10.4 PKI CA cert/key

Owner: PKI/CA service.

Dung de cap cert cho officer/thirdparty theo luong request/approve/download.

Runtime path:

```text
DEPLOY/D2/state/pki/ca_key.pem
DEPLOY/D2/state/pki/ca_cert.pem
DEPLOY/D2/state/pki/issued_certs.json
```

`ca_key.pem` la private key CA, can bao ve cao nhat. `ca_cert.pem` la public CA cert.

### 10.5 Officer business signing key

Owner: officer.

Dung de ky nghiep vu/tai lieu. Day la key khac voi key mTLS dang nhap.

DB chi luu public key va metadata:

```text
officer_keys.public_key_pem
officer_keys.key_version
```

Private key khong nen luu DB. Trong demo helper co the giu local; trien khai that nen nam trong USB token/HSM.

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
| `officer_keys` | Public key ky nghiep vu cua officer |
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
- Private key khong dua vao frontend.
- CA private key va domain private key khong nen commit len git.
- USB token/HSM nen giu private key trong trien khai that.
