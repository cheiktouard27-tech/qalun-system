import os,tempfile,unittest
from datetime import date
os.environ['QALUN_DB']=tempfile.mktemp(suffix='.sqlite3')
from app import app,db

class SystemTests(unittest.TestCase):
 def setUp(self):self.c=app.test_client()
 def login(self,name):
  r=self.c.post('/api/login',json={'username':name,'password':'Qalun@2026!'})
  self.assertEqual(r.status_code,200);self.h={'X-CSRF-Token':r.json['csrf']}
 def test_login_required(self):self.assertEqual(self.c.get('/api/students').status_code,401)
 def test_admin_pages(self):
  self.login('admin')
  for p in ['/meta','/students','/dashboard','/users','/circles','/settings','/schedules','/notifications','/reports/1','/receipts/1']:
   r=self.c.get('/api'+p);self.assertEqual(r.status_code,200,(p,r.json))
 def test_teacher_isolation(self):
  self.login('teacher');ss=self.c.get('/api/students').json
  self.assertTrue(ss);self.assertTrue(all(s['teacher_id']==2 for s in ss))
  self.assertEqual(self.c.get('/api/students/3').status_code,404)
  self.assertEqual(self.c.get('/api/reports/3').status_code,404)
  self.assertEqual(self.c.get('/api/records/payments').status_code,403)
  self.assertEqual(self.c.post('/api/records/monthly',json={'student_id':3},headers=self.h).status_code,404)
  self.assertEqual(self.c.get('/api/users').status_code,403)
 def test_agent_isolation(self):
  self.login('agent');ss=self.c.get('/api/students').json
  self.assertTrue(all(s['agent_id']==4 for s in ss));self.assertEqual(self.c.get('/api/students/2').status_code,404)
  r=self.c.get('/api/students/1').json;self.assertNotIn('finance',r);self.assertNotIn('payments',r['records'])
  self.assertEqual(self.c.post('/api/records/progress',json={'student_id':1},headers=self.h).status_code,403)
 def test_accountant(self):
  self.login('accountant');r=self.c.get('/api/students/1').json
  self.assertIn('finance',r);self.assertNotIn('progress',r['records']);self.assertNotIn('notes',r['student'])
  self.assertEqual(self.c.get('/api/records/monthly').status_code,403)
 def test_csrf(self):
  self.login('admin');self.assertEqual(self.c.post('/api/students',json={'name':'test'}).status_code,403)
 def test_attendance_upsert(self):
  self.login('teacher');d={'student_id':1,'date':date.today().isoformat(),'status':'present','note':'test'}
  for s in ['present','late']:
   d['status']=s;r=self.c.post('/api/records/attendance',json=d,headers=self.h);self.assertEqual(r.status_code,200,r.json)
  rr=self.c.get('/api/records/attendance?student=1&start='+d['date']+'&end='+d['date']).json
  self.assertEqual(len(rr),1);self.assertEqual(rr[0]['status'],'late')
 def test_student_transfer_and_delete(self):
  self.login('admin');d={'name':'طالب اختبار','registered':date.today().isoformat(),'circle_id':1,'agent_id':4,'status':'active','level':'مبتدئ'}
  r=self.c.post('/api/students',json=d,headers=self.h);self.assertEqual(r.status_code,200,r.json);sid=r.json['id'];admin_h=self.h.copy()
  teacher=app.test_client();tr=teacher.post('/api/login',json={'username':'teacher','password':'Qalun@2026!'})
  agent=app.test_client();agent.post('/api/login',json={'username':'agent','password':'Qalun@2026!'})
  self.assertEqual(teacher.get('/api/students/'+str(sid)).status_code,200)
  self.assertEqual(agent.get('/api/students/'+str(sid)).status_code,200)
  d.update(circle_id=3,agent_id=5);r=self.c.put('/api/students/'+str(sid),json=d,headers=admin_h);self.assertEqual(r.status_code,200,r.json)
  self.assertEqual(teacher.get('/api/students/'+str(sid)).status_code,404)
  self.assertEqual(agent.get('/api/students/'+str(sid)).status_code,404)
  self.assertEqual(self.c.delete('/api/students/'+str(sid),headers=admin_h).status_code,200)
 def test_financial_validation(self):
  self.login('admin');d={'student_id':1,'date':date.today().isoformat(),'amount':'-1'}
  self.assertEqual(self.c.post('/api/records/payments',json=d,headers=self.h).status_code,400)
  d['amount']='0.001';self.assertEqual(self.c.post('/api/records/payments',json=d,headers=self.h).status_code,400)
  self.assertEqual(self.c.delete('/api/students/1',headers=self.h).status_code,409)
 def test_disabled_account(self):
  self.login('teacher2')
  with db() as c:c.execute("UPDATE users SET status='paused' WHERE username='teacher2'")
  self.assertEqual(self.c.get('/api/students').status_code,401)
  with db() as c:c.execute("UPDATE users SET status='active' WHERE username='teacher2'")
 def test_report_period(self):
  self.login('admin');d=self.c.get('/api/reports/1?start=2000-01-01&end=2000-02-01').json
  self.assertEqual(d['records']['monthly'],[]);self.assertEqual(d['finance']['paid'],0)
 def test_archive_isolation(self):
  self.login('admin');r=self.c.post('/api/report-archive?start=1900-01-01&end='+date.today().isoformat(),json={'student_id':2},headers=self.h)
  self.assertEqual(r.status_code,200,r.json);rid=r.json['id']
  self.assertEqual(self.c.get('/api/report-archive/'+str(rid)).status_code,200)
  self.login('agent');self.assertEqual(self.c.get('/api/report-archive/'+str(rid)).status_code,404)
 def test_agent_finance_read_only(self):
  with db() as c:c.execute('UPDATE users SET permissions=? WHERE username=?',('["reports","finance"]','agent'))
  self.login('agent');self.assertEqual(self.c.get('/api/records/payments').status_code,200)
  self.assertEqual(self.c.post('/api/records/payments',json={'student_id':1},headers=self.h).status_code,403)
  self.assertEqual(self.c.get('/api/receipts/2').status_code,404)
  with db() as c:c.execute('UPDATE users SET permissions=? WHERE username=?',('["reports"]','agent'))
 def test_grades(self):
  self.login('teacher');d={'student_id':1,'date':date.today().isoformat(),'grade':105}
  self.assertEqual(self.c.post('/api/records/monthly',json=d,headers=self.h).status_code,400)

if __name__=='__main__':unittest.main(verbosity=2)
