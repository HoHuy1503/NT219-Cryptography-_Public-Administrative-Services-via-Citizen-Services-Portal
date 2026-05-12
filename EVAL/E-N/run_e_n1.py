# EVAL/E-N/run_e_n1.py
import requests, json
 
KC = 'http://localhost:8080/realms/master/protocol/openid-connect/token'
CLIENT_ID = 'admin-cli'
USERNAME = 'admin'
PASSWORD = 'AdminPass@2024'
 
def login(username, password):
    r = requests.post(KC, data={
        'grant_type': 'password',
        'client_id': CLIENT_ID,
        'username': username,
        'password': password
    })
    return r.status_code == 200
 
# 100 login đúng credential → phải ≥ 99% pass
success = sum(login(USERNAME, PASSWORD) for _ in range(100))
success_rate = success / 100 * 100
print(f'Success rate: {success_rate:.1f}% (threshold ≥99%)')
 
# 50 login sai credential → false-accept phải = 0
false_accepts = sum(login(USERNAME, f'WrongPass_{i}') for i in range(50))
print(f'False-accept: {false_accepts} (threshold = 0)')
 
# Test lockout: 5 sai liên tiếp
for i in range(6):
    r = requests.post(KC, data={
        'grant_type':'password','client_id':CLIENT_ID,
        'username':USERNAME,'password':'WRONGWRONGWRONG'
    })
    if i == 5:
        locked = r.status_code in [400, 401, 429]
        print(f'Lockout after 5 fails: {"PASS" if locked else "FAIL"}')
 
e_n1_pass = success_rate >= 99 and false_accepts == 0
print(f'E-N1: {"PASS" if e_n1_pass else "FAIL"}')
open('EVAL/E-N/E-N1-result.json','w').write(json.dumps({
    'eval_id':'E-N1','invariant':'I4',
    'success_rate':success_rate,'false_accepts':false_accepts,
    'status':'PASS' if e_n1_pass else 'FAIL'
},indent=2))
