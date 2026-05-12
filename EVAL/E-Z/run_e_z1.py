import requests, json
from datetime import datetime
 
OPA = 'http://localhost:8181/v1/data/govportal/authz'

def is_business_hours_now():
        now = datetime.now()
        return now.weekday() < 5 and 7 <= now.hour < 17

OFFICER_EXPECTED = is_business_hours_now()
 
cases = [
  ('TC-01','CITIZEN','u1','A','read', {'type':'application','owner':'u1','dept':'A'}, True,  'Citizen đọc hồ sơ mình'),
  ('TC-02','CITIZEN','u1','A','read', {'type':'application','owner':'u2','dept':'A'}, False, 'Citizen đọc hồ sơ người khác'),
    ('TC-03','OFFICER','o1','IT','approve',{'type':'application','owner':'u1','dept':'IT'},OFFICER_EXPECTED, 'Officer đúng phòng ban'),
  ('TC-04','OFFICER','o1','IT','approve',{'type':'application','owner':'u1','dept':'HR'},False,'Officer sai phòng ban'),
  ('TC-05','CITIZEN','u1','A','delete',{'type':'application','owner':'u1','dept':'A'}, False,'Citizen không được xóa'),
  ('TC-06','AUDITOR','a1','X','read',  {'type':'audit_log','owner':'sys','dept':'X'}, True, 'Auditor đọc log'),
  ('TC-07','AUDITOR','a1','X','delete',{'type':'audit_log','owner':'sys','dept':'X'}, False,'Auditor không được xóa log'),
  ('TC-08','ADMIN','ad','X','create_user',{'type':'user_management','dept':'X'},    True, 'Admin tạo user'),
]
 
results = []
for tc,role,uid,dept,action,res,expected,desc in cases:
    r = requests.post(OPA, json={'input':{
        'user':{'role':role,'id':uid,'dept':dept},
        'action':action,'resource':res}})
    got = r.json()['result']['allow']
    reason = r.json()['result'].get('deny_reason','')
    passed = (got == expected)
    print(f'[{"PASS" if passed else "FAIL"}] {tc}: {desc}')
    if not passed: print(f'       Expected {expected}, got {got}')
    if not got: print(f'       Reason: {reason}')
    results.append({'id':tc,'passed':passed,'reason':reason})
 
rate = sum(r['passed'] for r in results) / len(results) * 100
status = 'PASS' if rate >= 95 else 'FAIL'
print(f'E-Z1: {rate:.0f}% pass ({status}, threshold ≥95%) — I5')
open('EVAL/E-Z/E-Z1-result.json','w').write(
    json.dumps({'eval_id':'E-Z1','invariant':'I5',
                'pass_rate':rate,'cases':results,'status':status},indent=2))
