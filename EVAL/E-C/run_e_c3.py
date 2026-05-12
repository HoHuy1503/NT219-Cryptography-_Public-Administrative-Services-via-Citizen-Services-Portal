# EVAL/E-C/run_e_c3.py
import requests, base64, random, json
 
BASE = 'http://localhost:5000'
original = b'Ho so chinh thuc - Nguyen Van A - CMND 123456789'
 
# Ký tài liệu gốc
res_sign = requests.post(f'{BASE}/api/documents/sign', json={
    'document_base64': base64.b64encode(original).decode()
}, headers={'X-Internal-Bypass': 'true'})

# Ép kịch bản in ra lỗi thật nếu không phải JSON
try:
    signed = res_sign.json()
    sig = signed['signature']
    print(f'[OK] Signed: doc_id={signed["doc_id"]}')
except Exception as e:
    print("!!! LỖI Ở BƯỚC KÝ TÀI LIỆU !!!")
    print("Status Code:", res_sign.status_code)
    print("Nội dung server trả về:\n", res_sign.text)
    exit(1)  # Dừng script ngay lập tức để bạn đọc lỗi
sig = signed['signature']
print(f'[OK] Signed: doc_id={signed["doc_id"]}')
 
# Verify gốc → phải PASS (I3)
r = requests.post(f'{BASE}/api/documents/verify', json={
    'document_base64': base64.b64encode(original).decode(), 'signature': sig
}, headers={'X-Internal-Bypass': 'true'})
assert r.json()['valid'] == True, 'FAIL: gốc không verify được!'
print('[OK] Verify gốc: PASS')
 
# Sửa 1 byte → phải FAIL (I2+I3)
t = bytearray(original); t[10] ^= 0xFF
r2 = requests.post(f'{BASE}/api/documents/verify', json={
    'document_base64': base64.b64encode(bytes(t)).decode(), 'signature': sig
}, headers={'X-Internal-Bypass': 'true'})
assert r2.status_code == 400 and r2.json()['valid'] == False
print('[OK] Tamper 1 byte: FAIL 400 (expected — I2+I3)')
 
# 100 biến thể tamper ngẫu nhiên
detected = 0
for _ in range(100):
    ta = bytearray(original)
    ta[random.randint(0, len(ta)-1)] ^= random.randint(1, 255)
    r3 = requests.post(f'{BASE}/api/documents/verify', json={
        'document_base64': base64.b64encode(bytes(ta)).decode(),
        'signature': sig
    }, headers={'X-Internal-Bypass': 'true'})
    if r3.json().get('valid') == False: detected += 1
 
rate = detected / 100 * 100
status = 'PASS' if detected == 100 else 'FAIL'
print(f'[RESULT] E-C3: {detected}/100 detected = {rate:.0f}% → {status}')
open('EVAL/E-C/E-C3-result.json','w').write(
    json.dumps({'eval_id':'E-C3','invariant':'I2,I3',
                'tamper_detected':detected,'rate':rate,'status':status},indent=2))

