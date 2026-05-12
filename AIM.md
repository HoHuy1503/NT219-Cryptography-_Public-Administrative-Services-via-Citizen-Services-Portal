# AIM.md — Asset Inventory & Model
# NT219 Topic 11: Cổng Dịch Vụ Hành Chính Công
 
## A1 — Dữ liệu (Data Assets)
| Tài sản              | Trạng thái            | Độ nhạy  | Rủi ro chính              |
|----------------------|-----------------------|----------|---------------------------|
| Hồ sơ công dân (PDF) | at-rest, in-transit   | Tối mật  | Giả mạo, lộ thông tin     |
| Session/JWT data     | in-process            | Nhạy cảm | Session hijacking, replay  |
| Audit log            | at-rest               | Nhạy cảm | Xóa/sửa log               |
| QR payload           | in-transit            | Tối mật  | Intercept, clone QR        |
 
## A2 — Bí mật & Khóa
| Key               | Dùng cho         | Lưu ở         | Rotate   |
|-------------------|------------------|---------------|----------|
| KEK (AES-256)     | Mã hóa DEK       | Vault KMS     | 30 ngày  |
| ML-DSA-65 priv    | Ký tài liệu (FIPS 204) | Vault Transit | 90 ngày  |
| ML-KEM-768 priv   | KEK encapsulation (FIPS 203) | Vault | 30 ngày  |
| TOTP seed         | Sinh OTP         | DB (KEK-enc)  | Per user |
| Ed25519 priv      | Ký JWT token (internal) | Keycloak/Vault| 24h      |
 
## A3 — Danh tính
- Người dùng: CMND, email, WebAuthn authenticator
- Services: SPIFFE SVID (mTLS client cert từ Internal CA)
- Thiết bị: device fingerprint, DPoP keypair
 
## A4 — Trạng thái & Chính sách
- JWT claims: sub, role, dept, amr, iat, exp (15 phút)
- Roles: CITIZEN / OFFICER / ADMIN / AUDITOR
- OPA Rego: deny-by-default, RBAC + ABAC
 
## A5 — Hạ tầng tin cậy
- Internal CA (Vault PKI Engine)
- KMS: HashiCorp Vault 1.16
- JWKS Endpoint: PKI Authority /.well-known/jwks.json (RFC 7517, kid-indexed)
- SIEM: structured JSON log từ tất cả services
 
## 1.3 — Mục tiêu bảo vệ SMART
| Mục tiêu               | Đo bằng      | Ngưỡng     |
|------------------------|--------------|------------|
| 0 byte plaintext rò rỉ| Wireshark E-C1| 0 byte    |
| False-accept = 0       | E-N1          | 0%         |
| Policy pass-rate       | OPA E-Z1      | ≥ 95%      |
| Key rotate SLA         | Vault E-X1    | ≤ 10 phút  |
| Blast-radius           | TTL check     | ≤ 24h      |
