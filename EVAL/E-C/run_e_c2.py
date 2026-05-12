# EVAL/E-C/run_e_c2.py
import requests, concurrent.futures, json, time
 
BASE = 'http://localhost:5000'
ciphertexts = []
errors = []
 
def encrypt_one(i):
    import base64
    resp = requests.post(f'{BASE}/api/documents/sign', json={
        'document_base64': base64.b64encode(f'doc_{i}'.encode()).decode()
    }, headers={'X-Internal-Bypass': 'true'})
    if resp.status_code == 201:
        return resp.json()['ciphertext']
    return None
 
print('Chạy 10,000 encrypt song song (50 workers)...')
start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    results = list(ex.map(encrypt_one, range(10000)))
elapsed = time.time() - start
 
valid = [r for r in results if r]
unique = set(valid)
collision = len(valid) - len(unique)
 
status = 'PASS' if collision == 0 else 'FAIL'
print(f'Requests: {len(valid)}/10000 | Unique: {len(unique)} | Collision: {collision}')
print(f'E-C2: {status} (threshold: 0 collision) | {elapsed:.1f}s')
 
result = {'eval_id':'E-C2','invariant':'I1,I2',
          'requests':len(valid),'unique':len(unique),
          'collision':collision,'status':status}
open('EVAL/E-C/E-C2-result.json','w').write(json.dumps(result,indent=2))

