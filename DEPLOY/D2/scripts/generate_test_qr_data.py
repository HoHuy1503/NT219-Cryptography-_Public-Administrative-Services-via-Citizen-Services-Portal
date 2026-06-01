#!/usr/bin/env python3
"""
Generate test QR data for citizen portal QR scanning functionality
QR Format: key_b64|document_id|document_type|encrypted_doc_b64|metadata_json
"""

import base64
import hashlib
import json
import uuid
import sys
from datetime import datetime, timedelta

def generate_qr_payload(
    document_id=None,
    document_type="identity_card",
    citizen_name="Nguyễn Văn A",
    citizen_id_number="001234567890",
    citizen_dob="1990-05-15",
    document_content=None,
    officer_id="officer_001",
    officer_name="Trần Chính Phủ",
    signature_algorithm="ML-DSA-44",
    issue_date=None,
    expiry_date=None,
):
    """Generate a complete QR payload for testing"""
    
    # Generate IDs if not provided
    if not document_id:
        document_id = f"doc_{uuid.uuid4().hex[:12]}"
    
    if not issue_date:
        issue_date = datetime.now().isoformat()
    
    if not expiry_date:
        expiry_date = (datetime.now() + timedelta(days=365)).isoformat()
    
    # Create key material (simulating encrypted document key)
    key_material = hashlib.sha256(
        f"{document_id}:{issue_date}".encode()
    ).digest()
    key_b64 = base64.b64encode(key_material[:32]).decode()
    
    # Create document content if not provided
    if not document_content:
        if document_type == "identity_card":
            document_content = f"""
GIẤY CHỨNG MINH NHÂN DÂN
Số: {citizen_id_number}
Họ tên: {citizen_name}
Ngày sinh: {citizen_dob}
Nơi cấp: Công an TP. Hồ Chí Minh
Ngày cấp: {issue_date.split('T')[0]}
Ngày hết hạn: {expiry_date.split('T')[0]}
"""
        elif document_type == "certificate":
            document_content = f"""
HỮU HIỆU CHỨNG CHỈ - CERTIFICATE
Chứng chỉ số: {document_id}
Cấp cho: {citizen_name}
CMND: {citizen_id_number}
Loại: Chứng chỉ nhân viên công vụ
Cơ quan cấp: Sở Nội vụ Thành phố
Ngày cấp: {issue_date.split('T')[0]}
Ngày hết hạn: {expiry_date.split('T')[0]}
Trạng thái: Còn hiệu lực
"""
        elif document_type == "residence_book":
            document_content = f"""
SỔ HỘ KHẨU
Số: {document_id}
Địa chỉ: 123 Nguyễn Huệ, Quận 1, TP. Hồ Chí Minh
Chủ hộ: {citizen_name}
CMND: {citizen_id_number}
Cấp ngày: {issue_date.split('T')[0]}
Cơ quan cấp: Công an Phường Bến Nghé
"""
    
    # Encrypt document (base64 encode for testing)
    encrypted_doc_b64 = base64.urlsafe_b64encode(
        document_content.encode()
    ).decode().rstrip("=")  # Remove padding for compact format
    
    # Create metadata with signature simulation
    # In real scenario, this would contain actual ML-DSA-44 signature
    metadata = {
        "document_id": document_id,
        "document_type": document_type,
        "citizen_name": citizen_name,
        "citizen_id_number": citizen_id_number,
        "citizen_dob": citizen_dob,
        "issued_by": {
            "officer_id": officer_id,
            "officer_name": officer_name,
            "department": "Sở Nội vụ Thành phố",
            "agency_code": "01001"
        },
        "issue_date": issue_date,
        "expiry_date": expiry_date,
        "signature": {
            "algorithm": signature_algorithm,
            "timestamp": datetime.now().isoformat(),
            # Simulated signature (in real use, this is actual ML-DSA-44 signature)
            "value": base64.b64encode(
                hashlib.sha256(
                    f"{document_id}{citizen_id_number}{issue_date}".encode()
                ).digest()
            ).decode()
        },
        "verification": {
            "status": "valid",
            "verified_by": "portal_system",
            "verified_at": datetime.now().isoformat()
        },
        "offline_mode": True,
        "qr_version": "1.0"
    }
    
    # Build final QR payload
    qr_payload = f"{key_b64}|{document_id}|{document_type}|{encrypted_doc_b64}|{json.dumps(metadata)}"
    
    return {
        "qr_payload": qr_payload,
        "document_id": document_id,
        "document_type": document_type,
        "metadata": metadata,
        "key": key_b64,
    }


def main():
    """Generate multiple test QR samples"""
    
    test_cases = [
        # Test 1: Identity Card
        {
            "document_type": "identity_card",
            "citizen_name": "Nguyễn Văn A",
            "citizen_id_number": "001234567890",
            "citizen_dob": "1990-05-15",
            "officer_name": "Trần Chính Phủ",
            "officer_id": "officer_001",
        },
        # Test 2: Certificate
        {
            "document_type": "certificate",
            "citizen_name": "Phạm Thị B",
            "citizen_id_number": "002345678901",
            "citizen_dob": "1985-10-22",
            "officer_name": "Lê Đức Thịnh",
            "officer_id": "officer_002",
        },
        # Test 3: Residence Book
        {
            "document_type": "residence_book",
            "citizen_name": "Hoàng Minh C",
            "citizen_id_number": "003456789012",
            "citizen_dob": "1995-03-08",
            "officer_name": "Ngô Thị Thanh",
            "officer_id": "officer_003",
        },
        # Test 4: Expired Certificate
        {
            "document_type": "certificate",
            "citizen_name": "Võ Thị D",
            "citizen_id_number": "004567890123",
            "citizen_dob": "1988-07-12",
            "officer_name": "Phạm Hữu Phong",
            "officer_id": "officer_001",
            "expiry_date": (datetime.now() - timedelta(days=30)).isoformat(),
        },
    ]
    
    results = []
    for i, test_case in enumerate(test_cases, 1):
        qr_data = generate_qr_payload(**test_case)
        results.append({
            "test_case": i,
            "sample_name": f"{test_case['document_type']} - {test_case['citizen_name']}",
            "data": qr_data
        })
        print(f"\n{'='*80}")
        print(f"TEST CASE {i}: {test_case['document_type'].upper()}")
        print(f"{'='*80}")
        print(f"Citizen: {test_case['citizen_name']}")
        print(f"ID Number: {test_case['citizen_id_number']}")
        print(f"Officer: {test_case['officer_name']}")
        print(f"\nQR Payload (copy này vào 'Nhập payload QR từ tài liệu'):\n")
        print(qr_data["qr_payload"])
        print(f"\n{'-'*80}")
        print("Metadata:")
        print(json.dumps(qr_data["metadata"], indent=2, ensure_ascii=False))
    
    # Save all results to JSON file
    output_file = "test_qr_data.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n\n{'='*80}")
    print(f"✓ All test cases saved to: {output_file}")
    print(f"{'='*80}")
    
    return results


if __name__ == "__main__":
    main()
