# QR Test Data - Hướng Dẫn Sử Dụng

## 📋 Tổng Quan

Đây là dữ liệu test QR để kiểm thử chức năng quét QR trong **Cổng Công Dân**.

QR format: `key_b64|document_id|document_type|encrypted_doc_b64|metadata_json`

**Các thành phần:**
- `key_b64`: Khóa mã hóa tài liệu (Base64)
- `document_id`: ID tài liệu duy nhất
- `document_type`: Loại tài liệu (identity_card, certificate, residence_book)
- `encrypted_doc_b64`: Dữ liệu tài liệu mã hóa (Base64 URL-safe)
- `metadata_json`: Metadata bao gồm thông tin công dân, chữ ký ML-DSA-44, và metadata khác

---

## 🧪 Test Case 1: Giấy Chứng Minh Nhân Dân (Identity Card)

**Thông tin:**
- Công dân: Nguyễn Văn A
- CMND: 001234567890
- Ghi phát bởi: Trần Chính Phủ (officer_001)
- Trạng thái: Còn hiệu lực

**QR Payload (Copy vào portal):**
```
y7bPNt3E1YhpekmZDvDk4PMHInk3guNm7PfSQ17YvAQ=|doc_a5a5cea4d5f0|identity_card|CkdJ4bqkWSBDSOG7qE5HIE1JTkggTkjDgk4gRMOCTgpT4buROiAwMDEyMzQ1Njc4OTAKSOG7jSB0w6puOiBOZ3V54buFbiBWxINuIEEKTmfDoHkgc2luaDogMTk5MC0wNS0xNQpOxqFpIGPhuqVwOiBDw7RuZyBhbiBUUC4gSOG7kyBDaMOtIE1pbmgKTmfDoHkgY-G6pXA6IDIwMjYtMDYtMDEKTmfDoHkgaOG6v3QgaOG6oW46IDIwMjctMDYtMDEK|{"document_id": "doc_a5a5cea4d5f0", "document_type": "identity_card", "citizen_name": "Nguyễn Văn A", "citizen_id_number": "001234567890", "citizen_dob": "1990-05-15", "issued_by": {"officer_id": "officer_1", "officer_name": "CA Q1", "department": "CA Q1", "agency_code": "01001"}, "issue_date": "2026-06-01T08:01:52.814291", "expiry_date": "2027-06-01T08:01:52.814294", "signature": {"algorithm": "ML-DSA-44", "timestamp": "2026-06-01T08:01:52.814337", "value": "FZ0K3g7kinU2jG1T6/MxzXXMEpGyt6w0t6hN9WShHKE="}, "verification": {"status": "valid", "verified_by": "portal_system", "verified_at": "2026-06-01T08:01:52.814343"}, "offline_mode": true, "qr_version": "1.0"}
```

---

## 🧪 Test Case 2: Chứng Chỉ (Certificate)

**Thông tin:**
- Công dân: Phạm Thị B
- CMND: 002345678901
- Ghi phát bởi: Lê Đức Thịnh (officer_002)
- Trạng thái: Còn hiệu lực
- Chữ ký: ML-DSA-44

**QR Payload:**
```
J2isy+SzKOeJqH54v8OI5eFwbbxNfx7wGF3b1ISnbl0=|doc_2d02d44b06fa|certificate|Ckjhu65VIEhJ4buGVSBDSOG7qE5HIENI4buIIC0gQ0VSVElGSUNBVEUKQ2jhu6luZyBjaOG7iSBz4buROiBkb2NfMmQwMmQ0NGIwNmZhCkPhuqVwIGNobzogUGjhuqFtIFRo4buLIEIKQ01ORDogMDAyMzQ1Njc4OTAxCkxv4bqhaTogQ2jhu6luZyBjaOG7iSBuaMOibiB2acOqbiBjw7RuZyB24bulCkPGoSBxdWFuIGPhuqVwOiBT4bufIE7hu5lpIHbhu6UgVGjDoG5oIHBo4buRCk5nw6B5IGPhuqVwOiAyMDI2LTA2LTAxCk5nw6B5IGjhur90IGjhuqFuOiAyMDI3LTA2LTAxClRy4bqhbmcgdGjDoWk6IEPDsm4gaGnhu4d1IGzhu7FjCg|{"document_id": "doc_2d02d44b06fa", "document_type": "certificate", "citizen_name": "Phạm Thị B", "citizen_id_number": "002345678901", "citizen_dob": "1985-10-22", "issued_by": {"officer_id": "officer_002", "officer_name": "Lê Đức Thịnh", "department": "Sở Nội vụ Thành phố", "agency_code": "01001"}, "issue_date": "2026-06-01T08:01:52.814597", "expiry_date": "2027-06-01T08:01:52.814601", "signature": {"algorithm": "ML-DSA-44", "timestamp": "2026-06-01T08:01:52.814631", "value": "t3soeg+KLG2vayuNg6OD7eCGLrL6ttKl0pjQfBvrhtI="}, "verification": {"status": "valid", "verified_by": "portal_system", "verified_at": "2026-06-01T08:01:52.814635"}, "offline_mode": true, "qr_version": "1.0"}
```

---

## 🧪 Test Case 3: Sổ Hộ Khẩu (Residence Book)

**Thông tin:**
- Công dân: Hoàng Minh C
- CMND: 003456789012
- Ghi phát bởi: Ngô Thị Thanh (officer_003)
- Địa chỉ: 123 Nguyễn Huệ, Quận 1, TP. Hồ Chí Minh
- Trạng thái: Còn hiệu lực

**QR Payload:**
```
mWqqPIQgtyclg47P3AH+lDsT404erUX3Jm+6/rWVZn8=|doc_2d78bf5bf051|residence_book|ClPhu5QgSOG7mCBLSOG6qFUKU-G7kTogZG9jXzJkNzhiZjViZjA1MQrEkOG7i2EgY2jhu4k6IDEyMyBOZ3V54buFbiBIdeG7hywgUXXhuq1uIDEsIFRQLiBI4buTIENow60gTWluaApDaOG7pyBo4buZOiBIb8OgbmcgTWluaCBDCkNNTkQ6IDAwMzQ1Njc4OTAxMgpD4bqlcCBuZ8OgeTogMjAyNi0wNi0wMQpDxqEgcXVhbiBj4bqlcDogQ8O0bmcgYW4gUGjGsOG7nW5nIELhur9uIE5naMOpCg|{"document_id": "doc_2d78bf5bf051", "document_type": "residence_book", "citizen_name": "Hoàng Minh C", "citizen_id_number": "003456789012", "citizen_dob": "1995-03-08", "issued_by": {"officer_id": "officer_003", "officer_name": "Ngô Thị Thanh", "department": "Sở Nội vụ Thành phố", "agency_code": "01001"}, "issue_date": "2026-06-01T08:01:52.814867", "expiry_date": "2027-06-01T08:01:52.814869", "signature": {"algorithm": "ML-DSA-44", "timestamp": "2026-06-01T08:01:52.814883", "value": "7Qyeu2sFltXZjIz4ZoAT/ZhVHL8s9+QjsqO69D8wH+s="}, "verification": {"status": "valid", "verified_by": "portal_system", "verified_at": "2026-06-01T08:01:52.814887"}, "offline_mode": true, "qr_version": "1.0"}
```

---

## 🧪 Test Case 4: Chứng Chỉ Hết Hạn (Expired Certificate)

**Thông tin:**
- Công dân: Võ Thị D
- CMND: 004567890123
- Ghi phát bởi: Phạm Hữu Phong (officer_001)
- Trạng thái: **HẾT HIỆU LỰC** (hết hạn 30 ngày trước)
- Đây là test case để kiểm thử xác thực chữ ký hết hạn

**QR Payload:**
```
r9X2vG8k1Fw4mZ5jH0C3pD7eM2qL8tY6nS4aB5wR1vI=|doc_5e89c66d73bc|certificate|Ckjhu65VIEhJ4buGVSBDSOG7qE5HIENI4buIIC0gQ0VSVElGSUNBVEUKQ2jhu6luZyBjaOG7iSBz4buROiBkb2NfNWU4OWM2NmQ3M2JjCkPhuqVwIGNobzogVsOyIFRo4buLIEQKQ01ORDogMDA0NTY3ODkwMTIzCkxv4bqhaTogQ2jhu6luZyBjaOG7iSBuaMOibiB2acOqbiBjw7RuZyB24bulCkPGoSBxdWFuIGPhuqVwOiBT4bufIE7hu5lpIHbhu6UgVGjDoG5oIHBo4buRCk5nw6B5IGPhuqVwOiAyMDI1LTA1LTAyCk5nw6B5IGjhur90IGjhuqFuOiAyMDI2LTA1LTAyCgi4bHU6IEPDsm4gaGnhu4d1IGzhu7FjCg|{"document_id": "doc_5e89c66d73bc", "document_type": "certificate", "citizen_name": "Võ Thị D", "citizen_id_number": "004567890123", "citizen_dob": "1988-07-12", "issued_by": {"officer_id": "officer_001", "officer_name": "Phạm Hữu Phong", "department": "Sở Nội vụ Thành phố", "agency_code": "01001"}, "issue_date": "2025-05-02T08:01:52.000000", "expiry_date": "2026-05-02T08:01:52.000000", "signature": {"algorithm": "ML-DSA-44", "timestamp": "2025-05-02T08:01:52.000000", "value": "3pL7mK9jH4fX6wQ2bY8oP1sT5rU3vZ7cN6eM0gD4sF2="}, "verification": {"status": "expired", "verified_by": "portal_system", "verified_at": "2026-06-01T08:01:52.000000"}, "offline_mode": true, "qr_version": "1.0"}
```

---

## 🚀 Cách Sử Dụng

### Trong Cổng Công Dân:

1. Mở Cổng Công Dân portal (http://localhost:3000)
2. Chọn tab **"Quét QR"** từ menu navigation
3. Dán QR payload vào ô text "Nhập payload QR từ tài liệu"
4. Nhấn nút **"Quét & Xác Thực"**
5. Xem kết quả:
   - Document ID
   - Loại tài liệu
   - Thông tin công dân
   - Metadata đầy đủ
   - Trạng thái xác thực

### Kiểm thử các scenarios:

| Test Case | Scenario | Kỳ vọng |
|-----------|----------|---------|
| Test 1 | Identity card còn hạn | ✅ Xác thực thành công, metadata đầy đủ |
| Test 2 | Certificate còn hạn | ✅ Xác thực thành công, chữ ký ML-DSA-44 visible |
| Test 3 | Residence book | ✅ Xác thực thành công, địa chỉ cập nhật |
| Test 4 | Certificate hết hạn | ⚠️ Xác thực thành công nhưng status="expired" |

---

## 📊 Metadata Chi Tiết

Mỗi QR payload chứa metadata JSON với các trường:

```json
{
  "document_id": "doc_xxxxx",           // ID tài liệu duy nhất
  "document_type": "certificate",       // Loại: identity_card|certificate|residence_book
  "citizen_name": "Phạm Thị B",         // Tên công dân
  "citizen_id_number": "002345678901",  // CMND/CCCD
  "citizen_dob": "1985-10-22",          // Ngày sinh
  "issued_by": {
    "officer_id": "officer_002",         // ID cán bộ
    "officer_name": "Lê Đức Thịnh",     // Tên cán bộ
    "department": "Sở Nội vụ Thành phố", // Cơ quan ghi phát
    "agency_code": "01001"               // Mã cơ quan
  },
  "issue_date": "2026-06-01T08:01:52",  // Ngày ghi phát
  "expiry_date": "2027-06-01T08:01:52", // Ngày hết hạn
  "signature": {
    "algorithm": "ML-DSA-44",            // Post-quantum signature algorithm
    "timestamp": "2026-06-01T08:01:52",  // Thời gian ký
    "value": "t3soeg+KLG2vayuNg..."     // Chữ ký Base64
  },
  "verification": {
    "status": "valid",                   // Trạng thái: valid|expired|revoked
    "verified_by": "portal_system",      // Kiểm thử bởi
    "verified_at": "2026-06-01T08:01:52" // Thời gian kiểm thử
  },
  "offline_mode": true,                 // Chế độ offline
  "qr_version": "1.0"                   // Phiên bản QR format
}
```

---

## 🔐 Bảo Mật

- Tất cả QR data được mã hóa Base64 URL-safe
- Mỗi QR có khóa mã hóa riêng (32 bytes)
- Chữ ký sử dụng ML-DSA-44 (post-quantum cryptography)
- Metadata bao gồm timestamp xác thực và verification status

---

## 📁 Vị trí Files

- **Generator script**: `DEPLOY/D2/scripts/generate_test_qr_data.py`
- **Test data JSON**: `DEPLOY/D2/scripts/test_qr_data.json`
- **Documentation**: `DEPLOY/D2/scripts/TEST_QR_README.md` (file này)

---

## ✅ Checklist Kiểm Thử

- [ ] Test Case 1: Identity card - Verify citizen info displays correctly
- [ ] Test Case 2: Certificate - Verify ML-DSA-44 signature visible
- [ ] Test Case 3: Residence book - Verify address information
- [ ] Test Case 4: Expired cert - Verify status shows as expired
- [ ] Cross-portal: Verify QR data persists after login
- [ ] Error handling: Test with invalid/malformed QR data

---

Generated: 2026-06-01
Cryptography: ML-DSA-44 (Post-Quantum)
