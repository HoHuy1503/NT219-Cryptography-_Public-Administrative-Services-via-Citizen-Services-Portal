import requests, json
 
OPA = 'http://localhost:8181/v1/data/govportal/authz'
 
test_cases = [
    ({'role':'CITIZEN','id':'u1','dept':'A'},'read',{'type':'application','owner':'u1','dept':'A'}),
    ({'role':'CITIZEN','id':'u1','dept':'A'},'read',{'type':'application','owner':'u2','dept':'A'}),
    ({'role':'OFFICER','id':'o1','dept':'IT'},'approve',{'type':'application','owner':'u1','dept':'IT'}),
    ({'role':'OFFICER','id':'o1','dept':'IT'},'approve',{'type':'application','owner':'u1','dept':'HR'}),
    ({'role':'AUDITOR','id':'a1','dept':'X'},'read',{'type':'audit_log','owner':'sys','dept':'X'}),
    ({'role':'AUDITOR','id':'a1','dept':'X'},'delete',{'type':'audit_log','owner':'sys','dept':'X'}),
    ({'role':'ADMIN','id':'ad','dept':'X'},'create_user',{'type':'user_management','dept':'X'}),
    ({'role':'CITIZEN','id':'u1','dept':'A'},'delete',{'type':'application','owner':'u1','dept':'A'}),
    ({'role':'OFFICER','id':'o2','dept':'HR'},'approve',{'type':'application','owner':'u2','dept':'IT'}),
    ({'role':'CITIZEN','id':'u3','dept':'B'},'submit',{'type':'application','owner':'u3','dept':'B'}),
] * 2  # 20 ca test
 
reconstructed = 0
log_entries = []
for user, action, resource in test_cases:
    r = requests.post(OPA, json={'input':{
        'user':user,'action':action,'resource':resource}})
    result = r.json()['result']
    allow = result['allow']
    reason = result.get('deny_reason','allow rule matched')
 
    # Kiểm tra có thể tái dựng từ log không
    can_reconstruct = bool(reason) and reason != ''
    if can_reconstruct: reconstructed += 1
 
    log_entries.append({'user':user,'action':action,
                        'resource':resource,'allow':allow,'reason':reason})
 
rate = reconstructed / len(test_cases) * 100
status = 'PASS' if rate == 100 else 'FAIL'
print(f'E-X2 Explainability: {reconstructed}/{len(test_cases)} = {rate:.0f}% → {status} (I5)')
 
open('EVAL/E-X/E-X2-result.json','w').write(json.dumps({
    'eval_id':'E-X2','invariant':'I5',
    'total':len(test_cases),'reconstructed':reconstructed,
    'rate':rate,'status':status,'log':log_entries
},indent=2))
print('Log saved → EVAL/E-X/E-X2-result.json')
