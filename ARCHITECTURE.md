khon# Kiến Trúc Hệ Thống GovPortal PKI

## 1. Tổng Quan

Hệ thống GovPortal cung cấp cổng thông tin công cộng cho công dân và cán bộ công quyản ở Việt Nam, với hỗ trợ chữ ký số ML-DSA (post-quantum cryptography). Các thành phần chính giao tiếp qua gateway; secrets are provided via environment or mounted files for local deployments.

## 2. Sơ Đồ Thành Phần

```
┌─────────────────────────────────────────────────────────────┐
│                     INTERNET / CLIENTS                       │
└────────┬──────────────────┬──────────────────┬───────────────┘
         │                  │                  │
    ┌────▼────┐        ┌────▼────┐      ┌────▼────┐
    │ Citizen  │        │ Officer  │      │   PKI   │
    │ Portal   │        │ Portal   │      │ Admin   │
    └────┬────┘        └────┬────┘      └────┬────┘
         │                  │                │
         └──────────────────┼────────────────┘
                    │
           ┌────────▼────────┐
           │ Gateway / Kong   │  (mTLS, auth, routing)
           │ DMZ             │
           └────────┬────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
    ┌───▼───┐  ┌───▼──────┐  ┌─▼───────┐
    │ Doc   │  │ Storage  │  │Keycloak │
    │Service│  │Service   │  │Auth     │
    │ PKI   │  │Officers  │  │         │
    └───┬───┘  └───┬──────┘  └────┬────┘
        │          │              │
        └──────────┼──────────────┘
                   │
         ┌─────────▼─────────┐
         │ PostgreSQL DB     │  (officers, citizens, certs, keys)
         │                   │
         └───────────────────┘

         ┌─────────────────────┐
         │ (No central Vault)  │  (Secrets provided via env/files for local/dev)
         │ PKI Engine          │  (mTLS certs)
         │ Transit Engine      │  (encryption keys)
         └─────────────────────┘

         ┌─────────────────────┐
         │ Redis Cache         │  (sessions, temp data)
         └─────────────────────┘
```

## 3. Các Thành Phần Chi Tiết

### 3.1 Citizen Portal
- **Chức năng**: Công dân xem tài liệu, yêu cầu dịch vụ hành chính
- **Yêu cầu**: Đăng nhập bằng Keycloak
- **Trạng thái**: Khóa tất cả chức năng cho đến khi xác thực

### 3.2 Officer Portal  
- **Chức năng**: Cán bộ xem/ký tài liệu công dân, cấp dịch vụ
- **Yêu cầu**: Đăng nhập bằng Keycloak + có certificate ML-DSA hoạt động
- **Trạng thái**: Khóa tất cả cho đến khi xác thực + đã có cert

### 3.3 PKI Admin Portal
- **Chức năng**: Quản lý cấp certificate cho officer, xem audit log
- **Yêu cầu**: Đăng nhập bằng Keycloak + role PKI Admin
- **Chức năng chính**:
  - Cấp certificate ML-DSA cho officer mới
  - Xem danh sách pending key requests
  - Approve/ reject key rotation requests
  - Export public keys Officer

### 3.4 Doc Service (PKI Service)
- **Cổng**:  5000 (HTTP)
- **Chức năng chính**:
  - Cấp certificate cho Officer (ML-DSA-44)
  - Ký tài liệu bằng ML-DSA công ty
  - Xác thực chữ ký tài liệu
  - Quản lý kho certificate
- **Lưu trữ**:
  - Root CA (RSA-4096) tại `/state/pki_ca_key.pem`, `/state/pki_ca_cert.pem`
  - Certificate store tại `/state/pki_issued_certs.json`
  - ML-DSA public key tại `/state/ml_pub.bin`

### 3.5 Storage Service (Officer/Document Management)
- **Cổng**: 9003 (HTTP)
- **Chức năng chính**:
  - Lưu trữ metadata Officer (region, name, email)
  - Quản lý officer public key (nhận từ PKI)
  - Quản lý officer certificate (tính toán thumbprint)
  - Lưu trữ tài liệu đã ký
  - Audit log
- **Ràng buộc Database**:
  - 1 officer = tối đa 1 active certificate
  - Unique index trên `(officer_id, is_active=TRUE)`
  - Certificate cũ tự động revoke khi cấp mới

### 3.6 Keycloak
- **Cổng**: 8080 (HTTP) hoặc 8443 (HTTPS)
- **Chức năng**: 
  - Quản lý realm "govportal"
  - Xác thực Citizen bằng password
  - Xác thực Officer bằng password + certificate
  - Xác thực PKI Admin
  - Cấp JWT token cho API

### 3.7 Secrets Management
- For this deployment (local / compose) we do not run a Vault server. Services obtain secrets from environment variables or mounted files under `/state`.
- In production deployments, replace local file/env secrets with a secure secrets manager (HashiCorp Vault or cloud KMS).

### 3.8 PostgreSQL Database
- **Schemas chính**:
  - `citizens` - Thông tin công dân
  - `officers` - Thông tin cán bộ (region_code, email, name)
  - `officer_keys` - Public keys của officer (lưu trữ, không private key)
  - `officer_key_requests` - Yêu cầu cấp/rotate key
  - `officer_certificates` - Certificate được cấp (cert_id, thumbprint, expires_at, is_active)
  - `documents` - Tài liệu đã ký (doc_id, content_hash, status)
  - `signatures` - Chữ ký ML-DSA (signature_data, officer_id, doc_id)
  - `audit_log` - Audit trail tất cả hành động

## 4. Các Luồng Hoạt Động Chi Tiết

### 4.1 Luồng Registration & Login - Citizen

```
1. Citizen truy cập Citizen Portal
   └─> Portal kiểm tra: session có tại Redis?
       ├─ YES: Load session, return homepage
       └─ NO: Redirect sang Keycloak login

2. Keycloak login screen
   └─> Citizen nhập username/password
   └─> Keycloak xác thực trong database `citizens`
   └─> Nếu thành công: Cấp JWT token, redirect lại portal
   └─> Portal lưu session tại Redis (TTL: 1 giờ)

3. Citizen mở lại portal
   └─> Session có ✓ Cho phép vào
   └─> Lock tất cả UI nếu session hết: Require re-login
```

### 4.2 Luồng Registration & Login - Officer

```
1. Officer truy cập Officer Portal
   └─> Portal kiểm tra: session + certificate hoạt động?
       ├─ Không có session: Redirect Keycloak login
       ├─ Có session nhưng không cert: Lock UI
       └─ Có session + cert hoạt động: Cho phép vào

2. Keycloak login
   └─> Officer nhập username/password
   └─> Keycloak xác thực trong database `officers`
   └─> JWT token được cấp, redirect về portal
   └─> Portal check: SELECT is_active=TRUE from officer_certificates WHERE officer_id=?
   └─> Nếu keine cert hoạt động, lock UI + cảnh báo "Request certificate from PKI admin"

3. Officer vào PKI portal để xin cert
   └─> PKI admin cấp cert (xem Luồng 4.3)
   └─> Officer lần sau login sẽ thấy cert hoạt động
```

### 4.3 Luồng Cấp Certificate cho Officer (PKI Admin)

```
1. PKI Admin mở PKI Portal
   └─> Portal liệt kê pending key requests từ storage service
   └─> GET /api/storage/officer-key-requests/pending (filtered by status='pending')

2. PKI Admin chọn Officer, nhấn "Issue Certificate"
   └─> Gửi request tới doc-service:
       POST /api/pki/issue-certificate
       {
         "officer_id": "officer_001",
         "common_name": "officer_001@q12hcm.gov.vn",
         "organization": "Q12_HCM",
         "country": "VN",
         "purpose": "officer_identity"
       }

3. Doc-Service xử lý
   └─> _issue_identity_cert() được gọi
   └─> Check constraint: _officer_has_valid_cert(officer_id)?
       ├─ YES: Return 409 Conflict "Officer already has active cert"
       └─ NO: Tiếp tục

4. Doc-Service tạo ML-DSA certificate
   └─> Dùng OpenSSL 3.6.1 để tạo ML-DSA-44 keypair
   └─> Tạo CSR (Certificate Signing Request) với officer_id thông tin
   └─> Ký bằng Root CA (RSA-4096) certificate
   └─> Lưu cert vào `/state/pki_issued_certs.json`
   └─> Return cert + public key

5. Doc-Service đăng ký cert với storage
   └─> POST /api/storage/officers/{officer_id}/certificates
       {
         "cert_id": "cert-abc123def456",
         "certificate": "-----BEGIN CERTIFICATE-----...",
         "not_after": "2027-05-30T02:19:13Z"
       }

6. Storage-Service nhận
   └─> Check: SELECT is_active FROM officer_certificates WHERE officer_id AND is_active
       ├─ YES (cert cũ tồn tại): UPDATE ... SET is_active=FALSE, revoked_at=NOW()
       └─ NO: Tiếp tục
   └─> INSERT new cert vào database với is_active=TRUE
   └─> Tính toán thumbprint = SHA256(cert_der)
   └─> Write audit log: REGISTER_CERTIFICATE

7. Officer được cấp cert ✓
   └─> Officer login lại portal
   └─> Officer portal load cert hoạt động từ storage
   └─> UI unlocked, officer có thể ký tài liệu
```

### 4.4 Luồng Ký Tài Liệu - Officer

```
1. Officer upload tài liệu trên Officer Portal
   └─> Portal check: certificate hoạt động?
       ├─ NO: Show error "No active certificate"
       └─ YES: Tiếp tục

2. Portal gửi request ký đến doc-service
   └─> POST /api/documents/sign
       {
         "citizen_id": "citizen_001",
         "officer_id": "officer_001",
         "document_base64": "base64encodedcontent",
         "doc_id": "doc-uuid",
         "doc_type": "official_document",
         "doc_title": "Văn bản quyết định"
       }

3. Doc-Service xử lý
   └─> Check: ML_ENABLED && _openssl_available()?
       └─ NO: Return 500 "ML-DSA signing unavailable"

4. Sign document
   └─> Dùng load_or_create_ml_keys() lấy ML-DSA private key
   └─> Ký tài liệu bằng OpenSSL: `openssl pkeyutl -sign -rawin`
   └─> Trả về signature (base64)

5. Lưu chữ ký vào storage
   └─> POST /api/storage/documents
       {
         "doc_id": "doc-uuid",
         "citizen_id": "citizen_001",
         "officer_id": "officer_001",
         "signature_data": "base64signature",
         "signature_algorithm": "ML-DSA",
         "content_hash": "sha256hash",
         "status": "signed"
       }

6. Storage lưu vào database + audit
   └─> INSERT vào `documents` table
   └─> INSERT vào `signatures` table
   └─> INSERT audit log

7. Response trả về officer
   └─> doc_id, signature, key_version=1, archive_status
```

### 4.5 Luồng Xác Thực Tài Liệu - Công Dân / Bên Thứ 3

```
1. Công dân nhận tài liệu đã ký (file + chữ ký)

2. Công dân upload lên citizen portal để xác thực
   └─> POST /api/documents/verify
       {
         "document_base64": "base64content",
         "signature": "base64signature",
         "public_key_b64": "base64mldsa_pubkey",
         "signature_algorithm": "ML-DSA"
       }

3. Doc-Service xác thực
   └─> Check: signature_algorithm == 'ML-DSA'?
       └─ NO: Return error "Only ML-DSA verification supported"

4. Verify signature
   └─> Dùng verify_with_ml():
       - Gọi OpenSSL: `openssl pkeyutl -verify -rawin`
       - So sánh hash tài liệu với hash trong signature
   └─> Return: { "valid": true/false, "doc_hash": "..." }

5. Công dân xem kết quả
   └─> "✓ Tài liệu hợp lệ" hoặc "✗ Tài liệu bị giả mạo"
```

### 4.6 Luồng Key Rotation - Officer (Nếu mất key)

```
1. Officer gửi yêu cầu rotation
   └─> POST /api/storage/officers/{officer_id}/key-requests
       {
         "reason": "Lost private key",
         "old_key_id": "key-xxx"
       }

2. Storage-Service lưu request
   └─> INSERT vào `officer_key_requests` với status='pending'
   └─> Audit log

3. PKI Admin duyệt request
   └─> View pending requests trong PKI portal
   └─> POST /api/storage/officer-key-requests/{request_id}/approve

4. Storage-Service approve
   └─> UPDATE request status='approved'
   └─> Gửi signal tới doc-service để cấp cert mới
   └─> Doc-service tạo cert mới (xem Luồng 4.3)
   └─> Cert cũ tự động revoke
```

## 5. Ràng Buộc & Chính Sách

### 5.1 Certificate Policy
- **Officer Certificate**: 
  - Thuật toán: ML-DSA-44 (post-quantum, NIST approved)
  - Người ký: Root CA (RSA-4096)
  - Hiệu lực: 365 ngày
  - Số lượng: Tối đa 1 hoạt động trên cơ sở dữ liệu
  - Revocation: Tự động khi cấp cert mới

- **Root CA**:
  - Thuật toán: RSA-4096 (classical)
  - Hiệu lực: 3650 ngày (10 năm)

### 5.2 Authentication Policy
- **Citizen**: Password via Keycloak
- **Officer**: Password + Active Certificate
- **PKI Admin**: Password + PKI Admin role

### 5.3 Regional Compliance
- Mỗi Officer gắn với 1 region (VD: Q12_HCM)
- Storage service đảm bảo data locality (region_code)
- Audit log lưu đầy đủ region thông tin

### 5.4 Authorization (RBAC)
- `citizen`: Xem tài liệu cá nhân, yêu cầu dịch vụ
- `officer`: Xem/ký tài liệu công dân trong khu vực
- `pki_admin`: Quản lý certificate
- `storage_admin`: Quản lý dữ liệu storage

## 6. Công Nghệ Mã Hóa

### 6.1 Post-Quantum Cryptography (Officer)
- **ML-DSA-44**: Ký tài liệu (NIST FIPS 204)
- **ML-KEM-512**: Encapsulation session key cho QR (NIST FIPS 203)

### 6.2 Classical Cryptography
- **RSA-4096**: Root CA + Intermediate CA
- **ECDSA-P256**: mTLS certs (Kong gateway)
- **SHA-256**: Hashing tài liệu, thumbprint cert
- **AES-256-GCM**: Encryption keys handled by local state or external KMS in production

### 6.3 OpenSSL Version
- **OpenSSL 3.6.1**: Custom build trên host machine
- Provider modules: `/opt/openssl/lib64/ossl-modules`
- Support ML-DSA-44 & ML-KEM-512

## 7. Flows Tóm Tắt

| Luồng | Điểm bắt đầu | Điểm kết thúc | Thác tác chính |
|-------|-------------|-------------|--------------|
| Citizen Login | Citizen Portal | Keycloak | Xác thực password |
| Officer Login | Officer Portal | Keycloak + Certificate check | Xác thực + kiểm tra cert |
| Issue Officer Cert | PKI Admin | Doc-Service + Storage | Cấp ML-DSA cert |
| Sign Document | Officer Portal | Doc-Service | Ký ML-DSA |
| Verify Signature | Citizen Portal | Doc-Service | Xác thực ML-DSA |
| Rotate Key | Officer Portal | Storage + Doc-Service | Cấp cert mới, revoke cũ |

## 8. Database Relations

```
officers (officer_id, region_code, email, name)
    ├─ officer_keys (1:N) - public keys lịch sử
    ├─ officer_certificates (1:1 active) - cert hiện tại
    └─ signatures (1:N) - chữ ký đã thực hiện

citizens (citizen_id, email, name, phone)
    ├─ documents (1:N) - tài liệu của công dân
    └─ signatures (via doc_id) 

documents (doc_id, citizen_id, content_hash, status)
    ├─ signatures (1:N) - chữ ký trên tài liệu
    └─ certificate (via officer_id)

officer_certificates (cert_id, officer_id, is_active)
    └─ unique constraint (officer_id) WHERE is_active

audit_log (action, actor_id, resource_type, timestamp)
```

## 9. Ghi Chú Triển Khai

- **Docker Images**: doc-service, qr-service, storage-service dùng Python 3.11 slim + OpenSSL 3.6.1 bundle
- **Vagrant**: D2 dùng Vagrant + Ansible để provision 3 VM (internal, dmz, db)
- **Port Mapping**: Kong gateway (8010-8080) route tới backend services
- **mTLS**: Kong ← → Keycloak, Kong ← → Services dùng mTLS (ECDSA-P256)
- **Database**: PostgreSQL lưu tại VM "db", connection từ doc-service & storage-service
- **State Management**: Doc-service lưu state tại `/state/` volume mount
