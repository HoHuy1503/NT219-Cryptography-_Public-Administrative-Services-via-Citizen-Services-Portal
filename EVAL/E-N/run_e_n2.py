# EVAL/E-N/run_e_n2.py
import requests, json
 
QR = 'http://localhost:5002'
 
# Test 1: verify lần 1 → PASS, lần 2 → FAIL (I7)
gen = requests.post(f'{QR}/api/qr/generate', json={'user_id':'test_u1'})
qr_data = gen.json()['qr_data']
 
r1 = requests.post(f'{QR}/api/qr/verify', json={'qr_data': qr_data})
assert r1.status_code == 200 and r1.json()['valid']
print('[OK] Lần 1 verify: PASS')
 
r2 = requests.post(f'{QR}/api/qr/verify', json={'qr_data': qr_data})
assert r2.status_code == 401 and 'already used' in r2.json()['error']
print(f'[OK] Lần 2 replay: 401 — {r2.json()["error"]}')
 
# Test 50 QR khác nhau: tất cả replay đều bị block
blocked = 0
for i in range(50):
    g = requests.post(f'{QR}/api/qr/generate', json={'user_id':f'u_{i}'})
    qd = g.json()['qr_data']
    requests.post(f'{QR}/api/qr/verify', json={'qr_data': qd})  # dùng lần 1
    rep = requests.post(f'{QR}/api/qr/verify', json={'qr_data': qd})  # replay
    if rep.status_code == 401: blocked += 1
 
rate = blocked / 50 * 100
status = 'PASS' if blocked == 50 else 'FAIL'
print(f'[RESULT] E-N2: {blocked}/50 blocked = {rate:.0f}% → {status} (I7)')
open('EVAL/E-N/E-N2-result.json','w').write(json.dumps({
    'eval_id':'E-N2','invariant':'I4,I7',
    'replay_blocked':blocked,'rate':rate,'status':status
},indent=2))

