import requests, json, base64
GW = 'http://localhost:5000'
results = []
 
def check(name, token, expect_reject=True):
    r = requests.post(f'{GW}/api/documents/sign',
        headers={'Authorization': f'Bearer {token}'},
        json={'document_base64': base64.b64encode(b'test').decode()})
    rejected = r.status_code in [401, 403]
    passed = (rejected == expect_reject)
    print(f'[{"PASS" if passed else "FAIL"}] {name}: HTTP {r.status_code}')
    results.append({'name':name,'passed':passed,'status_code':r.status_code})
 
# Test 1: alg=none attack
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({'sub':'attacker','role':'ADMIN','exp':9999999999}).encode()).decode().rstrip('=')
alg_none_token = f'{header}.{payload}.'
check('alg=none attack', alg_none_token, expect_reject=True)
 
# Test 2: Completely fake token
check('Fake random token', 'not.a.valid.jwt.token', expect_reject=True)
 
# Test 3: Expired token (thay exp = thời gian cũ)
exp_payload = base64.b64encode(json.dumps({'sub':'u1','role':'CITIZEN','exp':1000000}).encode()).decode().rstrip('=')
expired_token = f'{header}.{exp_payload}.'
check('Expired token', expired_token, expect_reject=True)
 
# Test 4: Không có token → phải reject
r_no_token = requests.post(f'{GW}/api/documents/sign',
    json={'document_base64': base64.b64encode(b'test').decode()})
no_token_ok = r_no_token.status_code in [401, 422]
print(f'[{"PASS" if no_token_ok else "FAIL"}] No token → {r_no_token.status_code}')
results.append({'name':'no token','passed':no_token_ok})
 
rate = sum(r['passed'] for r in results) / len(results) * 100
status = 'PASS' if rate == 100 else 'FAIL'
print(f'E-Z2: {rate:.0f}% → {status} (I5)')
open('EVAL/E-Z/E-Z2-result.json','w').write(
    json.dumps({'eval_id':'E-Z2','invariant':'I5',
                'cases':results,'status':status},indent=2))

