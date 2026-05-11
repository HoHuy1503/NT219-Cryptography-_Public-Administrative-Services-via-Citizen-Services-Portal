# CRYPTO_SOLUTION.md — Giai Phap Mat Ma 3 Lop

## Lop 1 — CRYPTO: Bao ve du lieu

### 1.1 Tai sao ML-DSA-65 (FIPS 204) thay vi RSA-2048 / ECDSA?
RSA-2048 va ECDSA P-256 deu dua tren bai toan factoring/discrete-log, khong an toan dai han truoc rui ro quantum. Tai lieu hanh chinh cong can gia tri phap ly dai han, vi vay he thong uu tien bo tham so hau luong tu theo chuan NIST 2024.

Trong implementation hien tai, Vault Transit dang dung key ed25519 de demo quy trinh ky/xac minh on dinh. Lo trinh nang cap la map sang ML-DSA-65 backend khi stack ho tro day du trong production.

### 1.2 Tai sao AES-256-GCM thay vi CBC?
AES-GCM la AEAD, dong thoi bao dam confidentiality + integrity:
- Du lieu bi sua 1 byte se fail authentication tag.
- Co the phat hien tamper ngay tai buoc verify.

Dieu nay phu hop truc tiep voi I1/I2/I3 trong bo invariants.

### 1.3 Tai sao Envelope Encryption?
Envelope encryption tach DEK va KEK:
- Moi tai lieu mot khoa du lieu rieng, giam blast-radius.
- Rotate KEK nhanh ma khong can ma hoa lai toan bo du lieu.
- De audit vong doi key, phu hop E-X1.

## Lop 2 — AuthN: Xac thuc danh tinh

### 2.1 WebAuthn la primary factor
WebAuthn dua tren public-key, private key nam trong authenticator va khong roi thiet bi. Credential bi bind theo RP ID nen giam rui ro phishing va replay.

### 2.2 DPoP de chong token theft
Bearer token thong thuong co tinh chat "ai cam token deu dung duoc". DPoP rang buoc token voi private key phia client:
- Moi request kem proof JWT ky boi private key client.
- Gateway/Resource server verify proof truoc khi chap nhan token.

Huong nay giam false-accept trong E-N1 va tiep suc cho I4.

## Lop 3 — AuthZ: Cap quyen

### 3.1 OPA/Rego thay cho hardcode if-else
Hardcode logic cap quyen trong service tao no ky thuat: kho test, kho audit, kho thay doi.

OPA cho phep:
- Policy as code, version bang Git.
- Deny-by-default ro rang.
- Log duoc deny_reason de explainability (E-X2).
- Test matrix co the chay tu dong (E-Z1).

## Ket noi voi implementation trong repo
- Doc-service ky/xac minh va encrypt thong qua Vault Transit.
- QR-service enforce single-use nonce bang Redis de chong replay (I7).
- OPA policy gom RBAC + ABAC, quy tac theo role/dept/business-hours.
- Evaluation scripts E-C/E-N/E-Z/E-X map truc tiep sang 7 invariants I1..I7.
