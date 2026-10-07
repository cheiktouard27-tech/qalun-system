import os, io, json, sqlite3, csv, secrets, time, base64, re
from datetime import date, datetime, timedelta
from functools import wraps
from contextlib import contextmanager
from flask import Flask, request, jsonify, session, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash

ROOT=os.path.dirname(os.path.abspath(__file__))
app=Flask(__name__,static_folder='static')
os.makedirs(os.path.join(ROOT,'data'),exist_ok=True)
secret_path=os.path.join(ROOT,'data','session.key')
if not os.path.exists(secret_path):
    with open(secret_path,'w') as f:f.write(secrets.token_hex(48))
    os.chmod(secret_path,0o600)
app.secret_key=os.environ.get('SECRET_KEY') or open(secret_path).read()
from itsdangerous import Signer,TimestampSigner
auth_signer=TimestampSigner(app.secret_key+':auth')
csrf_signer=Signer(app.secret_key+':csrf')
SESSION_MAX_AGE=8*3600
def make_token(uid):return auth_signer.sign(str(uid)).decode()
def csrf_for(uid):return csrf_signer.sign(str(uid)).decode()
app.config.update(MAX_CONTENT_LENGTH=60*1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE')=='1',PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
DB=os.environ.get('QALUN_DB',os.path.join(ROOT,'data','qalun.sqlite3'))
import cloud_sync
cloud_sync.restore(DB)
DEFAULTS={'admin':['all'],'teacher':['attendance','progress','monthly','quarterly','reports'],'agent':['reports'],'accountant':['finance']}
TABLES={'attendance':['date','status','note'],'progress':['date','surah','juz','new_amount','review','mastery','errors','note'],'monthly':['date','period','memorization','review','recitation','grade','errors','note'],'quarterly':['date','period','memorization','review','recitation','grade','errors','note'],'charges':['date','due_date','amount','note'],'payments':['date','amount','note']}
LOGIN_ATTEMPTS={}

def log_login(ip,username,ok,reason=''):
    try:
        with open(os.path.join(ROOT,'data','login.log'),'a') as f:
            f.write('%s ip=%s user=%r ok=%s %s\n'%(datetime.now().isoformat(timespec='seconds'),ip,repr(username),ok,reason))
    except Exception: pass

@contextmanager
def db():
    c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=5000')
    try:
        yield c
        c.commit()
    except:
        c.rollback()
        raise
    finally:c.close()

def rows(c,q,args=()):return [dict(x) for x in c.execute(q,args).fetchall()]
def one(c,q,args=()):
    x=c.execute(q,args).fetchone();return dict(x) if x else None

def init_db():
 with db() as c:
    c.executescript('''
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','teacher','agent','accountant')),phone TEXT DEFAULT '',specialty TEXT DEFAULT '',status TEXT DEFAULT 'active',permissions TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS circles(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,teacher_id INTEGER REFERENCES users(id),level TEXT DEFAULT '',schedule TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE,name TEXT NOT NULL,birth_date TEXT DEFAULT '',phone TEXT DEFAULT '',guardian TEXT DEFAULT '',guardian_phone TEXT DEFAULT '',registered TEXT NOT NULL,circle_id INTEGER REFERENCES circles(id),agent_id INTEGER REFERENCES users(id),level TEXT DEFAULT '',status TEXT DEFAULT 'active',notes TEXT DEFAULT '',photo TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,date TEXT NOT NULL,status TEXT NOT NULL,note TEXT DEFAULT '',created_by INTEGER REFERENCES users(id),UNIQUE(student_id,date));
    CREATE TABLE IF NOT EXISTS progress(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,date TEXT NOT NULL,surah TEXT,juz INTEGER,new_amount TEXT,review TEXT,mastery REAL,errors TEXT,note TEXT,created_by INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS monthly(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,date TEXT NOT NULL,period TEXT,memorization TEXT,review TEXT,recitation TEXT,grade REAL,errors TEXT,note TEXT,created_by INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS quarterly(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,date TEXT NOT NULL,period TEXT,memorization TEXT,review TEXT,recitation TEXT,grade REAL,errors TEXT,note TEXT,created_by INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS charges(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,date TEXT NOT NULL,due_date TEXT NOT NULL,amount INTEGER NOT NULL CHECK(amount>0),note TEXT,created_by INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,date TEXT NOT NULL,amount INTEGER NOT NULL CHECK(amount>0),note TEXT,created_by INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,actor_id INTEGER REFERENCES users(id),date TEXT NOT NULL,action TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS schedules(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,type TEXT NOT NULL,date TEXT NOT NULL,circle_id INTEGER REFERENCES circles(id));
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS report_archive(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,created_by INTEGER REFERENCES users(id),created_at TEXT NOT NULL,start TEXT NOT NULL,end TEXT NOT NULL,payload TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS student_circle ON students(circle_id);
    CREATE INDEX IF NOT EXISTS student_agent ON students(agent_id);
    CREATE INDEX IF NOT EXISTS progress_student_date ON progress(student_id,date);
    CREATE INDEX IF NOT EXISTS monthly_student_date ON monthly(student_id,date);
    CREATE INDEX IF NOT EXISTS quarterly_student_date ON quarterly(student_id,date);
    CREATE INDEX IF NOT EXISTS charge_student_date ON charges(student_id,date);
    CREATE INDEX IF NOT EXISTS payment_student_date ON payments(student_id,date);
    CREATE INDEX IF NOT EXISTS attendance_date ON attendance(date);
    CREATE INDEX IF NOT EXISTS event_student ON events(student_id,id);
    ''')
    if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]:return
    if os.environ.get('QALUN_DEMO','1')=='0':
      initial_password=os.environ.get('ADMIN_PASSWORD','')
      if len(initial_password)<12:raise RuntimeError('ADMIN_PASSWORD must contain at least 12 characters for a new non-demo database')
      c.execute('INSERT INTO users(name,username,password,role,permissions) VALUES(?,?,?,?,?)',('مدير المعهد','admin',generate_password_hash(initial_password),'admin',json.dumps(['all'])))
      c.executemany('INSERT INTO settings VALUES(?,?)',[('institute','معهد قالون لتحفيظ القرآن الكريم'),('currency','MRU'),('demo','0')]);return
    names=[('مدير المعهد','admin','admin'),('أحمد عبد الرحمن','teacher','teacher'),('محمد الأمين','teacher2','teacher'),('عبد الله المختار','agent','agent'),('إبراهيم محمد','agent2','agent'),('محاسب المعهد','accountant','accountant')]
    for name,username,role in names:c.execute('INSERT INTO users(name,username,password,role,permissions,specialty) VALUES(?,?,?,?,?,?)',(name,username,generate_password_hash('Qalun@2026!'),role,json.dumps(DEFAULTS[role]),'رواية قالون' if role=='teacher' else ''))
    c.executemany('INSERT INTO settings VALUES(?,?)',[('institute','معهد قالون لتحفيظ القرآن الكريم'),('currency','MRU'),('demo','1')])
    for name,t,l,s in [('حلقة الإمام نافع',2,'متقدم','الأحد إلى الخميس · 16:00'),('حلقة الإمام قالون',2,'متوسط','الأحد إلى الخميس · 17:00'),('حلقة البراعم',3,'مبتدئ','الأحد إلى الخميس · 15:00'),('حلقة الإتقان',3,'متقدم','السبت والاثنين · 18:00')]:c.execute('INSERT INTO circles(name,teacher_id,level,schedule) VALUES(?,?,?,?)',(name,t,l,s))
    student_names=['عبد الرحمن محمد','محمد عبد الله','أحمد المختار','مريم أحمد','فاطمة محمد','يوسف إبراهيم','خديجة عبد الرحمن','عمر محمود','عائشة الحسن','إسماعيل أحمد','آمنة المختار','عبد الله يوسف','زينب محمد','الحسن إبراهيم','سلمى عبد الله','محمد الأمين','أسماء أحمد','إبراهيم الحسن','حفصة محمود','عثمان محمد','رقية عبد الله','بلال أحمد','محمود المختار','نور الهدى محمد']
    today=date.today()
    for i,n in enumerate(student_names,1):
      circle=(i-1)%4+1
      c.execute('INSERT INTO students(id,code,name,birth_date,guardian,registered,circle_id,agent_id,level,status) VALUES(?,?,?,?,?,?,?,?,?,?)',(i,f'QL-{i:04}',n,f'{2009+i%7}-03-12','ولي أمر '+n,(today-timedelta(days=180+i)).isoformat(),circle,4 if i%2 else 5,['متقدم','متوسط','مبتدئ','متقدم'][circle-1],'active' if i!=24 else 'paused'))
      for d in range(15):
        dt=(today-timedelta(days=d)).isoformat();st='absent' if (i+d)%11==0 else 'late' if (i+d)%13==0 else 'excused' if (i+d)%23==0 else 'present'
        c.execute('INSERT INTO attendance(student_id,date,status,note,created_by) VALUES(?,?,?,?,?)',(i,dt,st,'',2 if circle<3 else 3))
      for d in [0,7,15,30,60]:
        dt=(today-timedelta(days=d)).isoformat()
        c.execute('INSERT INTO progress(student_id,date,surah,juz,new_amount,review,mastery,errors,note,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',(i,dt,['البقرة','آل عمران','النبأ','الملك'][circle-1],[1,3,30,29][circle-1],'وجه واحد','خمسة أوجه',min(100,70+i%25+(60-d)/10),'تنبيه في المدود','تحسّن ملحوظ في التلاوة',2 if circle<3 else 3))
      for d in [0,30,60]:
        dt=(today-timedelta(days=d)).isoformat()
        c.execute('INSERT INTO monthly(student_id,date,period,memorization,review,recitation,grade,errors,note,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',(i,dt,dt[:7],'الجزء المقرر','المحفوظ السابق','أحكام المدود',min(100,72+i%20+(60-d)/10),'خطآن','يحتاج إلى تثبيت المراجعة',2))
      for d in [10,100]:
        dt=(today-timedelta(days=d)).isoformat()
        c.execute('INSERT INTO quarterly(student_id,date,period,memorization,review,recitation,grade,errors,note,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',(i,dt,'دورة '+dt[:7],'ثلاثة أجزاء','مراجعة شاملة','تجويد وتلاوة',min(100,70+i%22+(100-d)/20),'','أداء طيب أمام اللجنة',2))
      for d in [60,30,0]:
        dt=(today-timedelta(days=d)).isoformat()
        c.execute('INSERT INTO charges(student_id,date,due_date,amount,note,created_by) VALUES(?,?,?,?,?,1)',(i,dt,(today-timedelta(days=d)+timedelta(days=5)).isoformat(),50000,'رسوم تعليمية تجريبية'))
      c.execute('INSERT INTO payments(student_id,date,amount,note,created_by) VALUES(?,?,?,?,1)',(i,today.isoformat(),50000 if i%5==0 else 100000 if i%3 else 150000,'دفعة تجريبية'))
      c.execute('INSERT INTO events(student_id,actor_id,date,action) VALUES(?,1,?,?)',(i,datetime.now().isoformat(timespec='seconds'),'إنشاء ملف الطالب التجريبي'))
    for title,typ,days in [('اختبار الحفظ الشهري','monthly',5),('امتحان الدورة القرآنية','quarterly',14)]:c.execute('INSERT INTO schedules(title,type,date) VALUES(?,?,?)',(title,typ,(today+timedelta(days=days)).isoformat()))

def fail(msg,status=400):return jsonify(error=msg),status

def current():
    uid=session.get('uid')
    tok=request.headers.get('X-Auth-Token','')
    if tok:
        try:uid=int(auth_signer.unsign(tok,max_age=SESSION_MAX_AGE))
        except Exception:uid=None
    if uid is None:return None
    with db() as c:u=one(c,'SELECT * FROM users WHERE id=?',(uid,))
    if u:u['permissions']=json.loads(u['permissions']);u.pop('password',None)
    return u if u and u['status']=='active' else None

def has(u,perm):return u['role']=='admin' or perm in u['permissions']
def scope(u,alias='s'):
    if u['role'] in ['admin','accountant'] or has(u,'read_all'):return '1=1',[]
    if u['role']=='teacher':return f'{alias}.circle_id IN (SELECT id FROM circles WHERE teacher_id=?)',[u['id']]
    return f'{alias}.agent_id=?',[u['id']]

def access(c,u,sid):
    q,a=scope(u);return one(c,f'SELECT s.* FROM students s WHERE s.id=? AND {q}',[sid]+a)

def secured(fn):
 @wraps(fn)
 def wrapped(*a,**kw):
    u=current()
    if not u:return fail('يرجى تسجيل الدخول',401)
    if request.method not in ['GET','HEAD'] and not secrets.compare_digest(request.headers.get('X-CSRF-Token',''),csrf_for(u['id'])):return fail('رمز الحماية غير صالح؛ أعد تسجيل الدخول',403)
    return fn(u,*a,**kw)
 return wrapped

def audit(c,u,sid,action):c.execute('INSERT INTO events(student_id,actor_id,date,action) VALUES(?,?,?,?)',(sid,u['id'],datetime.now().isoformat(timespec='seconds'),action))
def valid_date(x):
    try:date.fromisoformat(x);return True
    except:return False

def dates():
    start=request.args.get('start','1900-01-01');end=request.args.get('end','9999-12-31')
    if not valid_date(start) or not valid_date(end) or start>end:raise ValueError('الفترة الزمنية غير صالحة')
    return start,end

def safe_user(u):u=dict(u);u.pop('password',None);u['permissions']=json.loads(u['permissions']) if isinstance(u['permissions'],str) else u['permissions'];return u

def finance(c,sid,start='1900-01-01',end='9999-12-31'):
    charges=c.execute('SELECT COALESCE(SUM(amount),0) FROM charges WHERE student_id=? AND date<=?',(sid,end)).fetchone()[0]
    paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE student_id=? AND date<=?',(sid,end)).fetchone()[0]
    due=c.execute('SELECT COALESCE(SUM(amount),0) FROM charges WHERE student_id=? AND date<=? AND due_date<?',(sid,end,min(end,date.today().isoformat()))).fetchone()[0]
    period_paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE student_id=? AND date BETWEEN ? AND ?',(sid,start,end)).fetchone()[0]
    return dict(charged=charges/100,paid=paid/100,balance=(charges-paid)/100,overdue=max(0,due-paid)/100,period_paid=period_paid/100)

@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff';r.headers['Referrer-Policy']='same-origin'
    if request.path.startswith('/api/'):r.headers['Cache-Control']='no-store'
    if request.method in ('POST','PUT','PATCH','DELETE') and request.path.startswith('/api/') and r.status_code<400 and request.path not in ('/api/login','/api/logout'):cloud_sync.schedule(DB)
    return r
@app.get('/api/sync-status')
def sync_status():return jsonify(cloud_sync.status())
@app.errorhandler(ValueError)
def validation(e):return fail(str(e))
@app.errorhandler(sqlite3.IntegrityError)
def integrity(e):return fail('تعذّر الحفظ: بيانات مكررة أو ارتباط غير صالح. تحقق من الحقول.',409)
@app.errorhandler(413)
def too_large(e):return fail('حجم الملف أكبر من الحد المسموح',413)
@app.get('/')
def index():return send_from_directory(app.static_folder,'index.html')
@app.get('/api/public-config')
def public_config():
 with db() as c:
    return jsonify(demo=c.execute("SELECT value FROM settings WHERE key='demo'").fetchone()[0]=='1')

@app.get('/api/session')
def get_session():
    u=current();return jsonify(user=u,csrf=csrf_for(u['id']) if u else None)
@app.post('/api/login')
def login():
    data=request.get_json(silent=True) or {};ip=request.remote_addr;now=time.time();attempts=[t for t in LOGIN_ATTEMPTS.get(ip,[]) if now-t<300]
    if len(attempts)>=20:return fail('محاولات كثيرة. انتظر خمس دقائق.',429)
    username=str(data.get('username','')).strip();password=str(data.get('password',''))
    with db() as c:u=one(c,'SELECT * FROM users WHERE lower(username)=lower(?)',(username,))
    if not u:
        log_login(ip,username,False,'user-not-found');LOGIN_ATTEMPTS[ip]=attempts+[now];return fail('اسم المستخدم أو كلمة المرور غير صحيحة',401)
    if not check_password_hash(u['password'],password):
        log_login(ip,username,False,'wrong-password');LOGIN_ATTEMPTS[ip]=attempts+[now];return fail('اسم المستخدم أو كلمة المرور غير صحيحة',401)
    if u['status']!='active':
        log_login(ip,username,False,'account-disabled');return fail('هذا الحساب موقوف. تواصل مع الإدارة.',403)
    log_login(ip,username,True)
    session.clear();session.permanent=True;session['uid']=u['id'];LOGIN_ATTEMPTS.pop(ip,None)
    return jsonify(user=safe_user(u),csrf=csrf_for(u['id']),token=make_token(u['id']))
@app.post('/api/logout')
@secured
def logout(u):session.clear();return jsonify(ok=True)
@app.post('/api/password')
@secured
def password(u):
    d=request.json or {};new=str(d.get('new',''))
    with db() as c:
      old=c.execute('SELECT password FROM users WHERE id=?',(u['id'],)).fetchone()[0]
      if not check_password_hash(old,str(d.get('old',''))):return fail('كلمة المرور الحالية غير صحيحة')
      if len(new)<10:return fail('كلمة المرور الجديدة يجب ألا تقل عن 10 أحرف')
      c.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new),u['id']))
    return jsonify(ok=True)
@app.get('/api/meta')
@secured
def meta(u):
 with db() as c:
    circles=rows(c,'SELECT c.*,u.name teacher_name FROM circles c LEFT JOIN users u ON u.id=c.teacher_id')
    if u['role']=='teacher' and not has(u,'read_all'):circles=[x for x in circles if x['teacher_id']==u['id']]
    if u['role']=='agent' and not has(u,'read_all'):circles=[x for x in circles if c.execute('SELECT 1 FROM students WHERE circle_id=? AND agent_id=?',(x['id'],u['id'])).fetchone()]
    users=rows(c,'SELECT id,name,role,status FROM users') if u['role']=='admin' else []
    return jsonify(circles=circles,users=users,settings={x['key']:x['value'] for x in rows(c,'SELECT * FROM settings')},today=date.today().isoformat())

STUDENT_QUERY='''SELECT s.*, c.name circle_name,c.teacher_id,u.name teacher_name,a.name agent_name FROM students s LEFT JOIN circles c ON c.id=s.circle_id LEFT JOIN users u ON u.id=c.teacher_id LEFT JOIN users a ON a.id=s.agent_id'''
@app.get('/api/students')
@secured
def students(u):
 with db() as c:
    q,a=scope(u);w=[q]
    if request.args.get('q'):w.append('(s.name LIKE ? OR s.code LIKE ?)');a += ['%'+request.args['q']+'%']*2
    for key,col in [('circle','s.circle_id'),('teacher','c.teacher_id'),('agent','s.agent_id'),('level','s.level'),('status','s.status')]:
      if request.args.get(key):w.append(col+'=?');a.append(request.args[key])
    result=rows(c,STUDENT_QUERY+' WHERE '+' AND '.join(w)+' ORDER BY s.id DESC',a)
    for s in result:
      s.pop('photo',None)
      if has(u,'finance'):s['finance']=finance(c,s['id'])
      if u['role']=='accountant':
        for key in ['birth_date','guardian','guardian_phone','notes']:s.pop(key,None)
    return jsonify(result)

@app.route('/api/students',methods=['POST'])
@app.route('/api/students/<int:sid>',methods=['PUT','DELETE'])
@secured
def mutate_student(u,sid=None):
 if u['role']!='admin':return fail('هذه العملية للمدير فقط',403)
 with db() as c:
    old=one(c,'SELECT * FROM students WHERE id=?',(sid,)) if sid else None
    if sid and not old:return fail('الطالب غير موجود',404)
    if request.method=='DELETE':
      if c.execute('SELECT 1 FROM payments WHERE student_id=?',(sid,)).fetchone() or c.execute('SELECT 1 FROM charges WHERE student_id=?',(sid,)).fetchone():return fail('للـطالب قيود مالية. أوقف الطالب بدل حذفه للحفاظ على السجلات.',409)
      audit(c,u,None,'حذف الطالب '+old['code']+' '+old['name']);c.execute('DELETE FROM students WHERE id=?',(sid,));return jsonify(ok=True)
    d=request.json or {};keys=['name','birth_date','phone','guardian','guardian_phone','registered','circle_id','agent_id','level','status','notes','photo'];d={k:d.get(k,old.get(k) if old else '') for k in keys}
    if not str(d['name']).strip() or len(d['name'])>120:return fail('اسم الطالب مطلوب، حتى 120 حرفًا')
    d['registered']=d['registered'] or date.today().isoformat()
    if not valid_date(d['registered']) or d['birth_date'] and (not valid_date(d['birth_date']) or d['birth_date']>date.today().isoformat()):return fail('تاريخ غير صالح')
    if d['status'] not in ['active','paused','graduated']:return fail('حالة الطالب غير صالحة')
    for key,table,role in [('circle_id','circles',None),('agent_id','users','agent')]:
      d[key]=int(d[key]) if d[key] else None
      if d[key] and not one(c,f'SELECT id FROM {table} WHERE id=?'+(' AND role=?' if role else ''),[d[key]]+([role] if role else [])):return fail('الحلقة أو الوكيل غير صالح')
    if d['photo']:
      if not re.match(r'^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$',d['photo']) or len(d['photo'])>700000:return fail('اختر صورة JPEG أو PNG أو WebP أصغر من 500 كيلوبايت')
    if sid:
      c.execute('UPDATE students SET '+','.join(k+'=?' for k in keys)+' WHERE id=?',[d[k] for k in keys]+[sid]);audit(c,u,sid,'تحديث بيانات الطالب أو الحلقة أو الوكيل')
    else:
      sid=c.execute('INSERT INTO students('+','.join(keys)+') VALUES('+','.join('?' for k in keys)+')',[d[k] for k in keys]).lastrowid
      c.execute('UPDATE students SET code=? WHERE id=?',(f'QL-{sid:04}',sid));audit(c,u,sid,'إضافة طالب جديد')
    return jsonify(id=sid)

@app.get('/api/students/<int:sid>')
@secured
def student_detail(u,sid):
 with db() as c:
    if not access(c,u,sid):return fail('الطالب غير موجود أو خارج صلاحياتك',404)
    start,end=dates();s=one(c,STUDENT_QUERY+' WHERE s.id=?',(sid,));result={'student':s,'records':{}}
    tables=['charges','payments'] if u['role']=='accountant' else ['attendance','progress','monthly','quarterly']+(['charges','payments'] if has(u,'finance') else [])
    for t in tables:
      rec=rows(c,f'SELECT r.*,u.name author FROM {t} r LEFT JOIN users u ON u.id=r.created_by WHERE student_id=? AND date BETWEEN ? AND ? ORDER BY date DESC,r.id DESC',(sid,start,end))
      if t in ['charges','payments']:
        for x in rec:x['amount']/=100
      result['records'][t]=rec
    if has(u,'finance'):result['finance']=finance(c,sid,start,end)
    result['events']=rows(c,'SELECT e.*,u.name actor FROM events e LEFT JOIN users u ON u.id=e.actor_id WHERE student_id=? AND substr(date,1,10) BETWEEN ? AND ? ORDER BY date DESC LIMIT 100',(sid,start,end)) if u['role']!='accountant' else []
    if u['role']=='accountant':
      for key in ['notes','birth_date','guardian','guardian_phone']:s.pop(key,None)
    return jsonify(result)

@app.route('/api/records/<kind>',methods=['GET','POST'])
@app.route('/api/records/<kind>/<int:rid>',methods=['PUT','DELETE'])
@secured
def records(u,kind,rid=None):
 if kind not in TABLES:return fail('القسم غير موجود',404)
 perm='finance' if kind in ['charges','payments'] else kind
 if u['role']=='accountant' and perm!='finance':return fail('غير مصرح',403)
 if request.method!='GET' and (not has(u,perm) or u['role']=='agent'):return fail('ليس لديك إذن تعديل هذا القسم',403)
 if perm=='finance' and not has(u,'finance'):return fail('ليست لديك صلاحية مالية',403)
 with db() as c:
    if request.method=='GET':
      start,end=dates();q,a=scope(u);w=[q,'r.date BETWEEN ? AND ?'];a += [start,end]
      if request.args.get('student'):w.append('s.id=?');a.append(request.args['student'])
      if request.args.get('circle'):w.append('s.circle_id=?');a.append(request.args['circle'])
      rec=rows(c,f'SELECT r.*,s.name student_name,s.code,c.name circle_name,u.name author FROM {kind} r JOIN students s ON s.id=r.student_id LEFT JOIN circles c ON c.id=s.circle_id LEFT JOIN users u ON u.id=r.created_by WHERE '+ ' AND '.join(w)+' ORDER BY r.date DESC,r.id DESC',a)
      if perm=='finance':
        for r in rec:r['amount']/=100
      return jsonify(rec)
    d=request.get_json(silent=True) or {};old=one(c,f'SELECT * FROM {kind} WHERE id=?',(rid,)) if rid else None
    if rid and not old:return fail('السجل غير موجود',404)
    sid=old['student_id'] if old else int(d.get('student_id') or 0)
    if not access(c,u,sid):return fail('الطالب غير موجود أو خارج صلاحياتك',404)
    if request.method=='DELETE':
      if perm=='finance':return fail('لا يسمح بحذف القيود المالية من هذه النسخة؛ احتفظ بأثر محاسبي',403)
      c.execute(f'DELETE FROM {kind} WHERE id=?',(rid,));audit(c,u,sid,'حذف سجل '+kind);return jsonify(ok=True)
    if old and perm=='finance':return fail('لا يسمح بتعديل القيود المالية بعد إثباتها',403)
    vals={k:d.get(k,old.get(k) if old else '') for k in TABLES[kind]}
    if not valid_date(vals['date']) or vals['date']>date.today().isoformat():return fail('تاريخ التسجيل يجب ألا يكون في المستقبل')
    if kind=='attendance' and vals['status'] not in ['present','absent','late','excused']:return fail('حالة حضور غير صالحة')
    for key in ['grade','mastery']:
      if key in vals:
        vals[key]=float(vals[key]);
        if not 0<=vals[key]<=100:return fail('الدرجة يجب أن تكون بين 0 و100')
    if kind=='progress':
      vals['juz']=int(vals['juz'])
      if not 1<=vals['juz']<=30 or not vals['surah']:return fail('السورة والجزء من 1 إلى 30 مطلوبان')
    if perm=='finance':
      from decimal import Decimal,InvalidOperation
      try:v=Decimal(str(vals['amount']));vals['amount']=int(v*100)
      except (InvalidOperation,ValueError,OverflowError):return fail('المبلغ غير صالح')
      if vals['amount']<=0 or vals['amount']>1000000000 or Decimal(vals['amount'])/100!=v:return fail('أدخل مبلغًا موجبًا حتى منزلتين عشريتين')
      if kind=='charges' and (not valid_date(vals['due_date']) or vals['due_date']<vals['date']):return fail('الاستحقاق يجب أن يكون في تاريخ القيد أو بعده')
    keys=list(vals)
    if rid:c.execute(f'UPDATE {kind} SET '+','.join(k+'=?' for k in keys)+' WHERE id=?',[vals[k] for k in keys]+[rid])
    elif kind=='attendance':
      c.execute('INSERT INTO attendance(student_id,date,status,note,created_by) VALUES(?,?,?,?,?) ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status,note=excluded.note,created_by=excluded.created_by',(sid,vals['date'],vals['status'],vals['note'],u['id']))
    else:rid=c.execute(f'INSERT INTO {kind}(student_id,'+','.join(keys)+',created_by) VALUES('+','.join('?' for _ in range(len(keys)+2))+')',[sid]+[vals[k] for k in keys]+[u['id']]).lastrowid
    audit(c,u,sid,{'attendance':'تحديث سجل الحضور','progress':'تسجيل حفظ ومراجعة','monthly':'إضافة نتيجة اختبار شهري','quarterly':'إضافة نتيجة امتحان دوري','charges':'إثبات رسوم مستحقة','payments':'تسجيل دفعة مالية'}[kind]);return jsonify(ok=True,id=rid)

@app.route('/api/users',methods=['GET','POST'])
@app.route('/api/users/<int:uid>',methods=['PUT'])
@secured
def users(u,uid=None):
 if u['role']!='admin':return fail('للمدير فقط',403)
 with db() as c:
    if request.method=='GET':return jsonify([safe_user(x) for x in rows(c,'SELECT * FROM users ORDER BY id')])
    d=request.json or {};old=one(c,'SELECT * FROM users WHERE id=?',(uid,)) if uid else None
    if uid and not old:return fail('الحساب غير موجود',404)
    role=d.get('role','')
    if role not in DEFAULTS or not str(d.get('name','')).strip() or not re.match(r'^[a-zA-Z0-9_.-]{3,40}$',d.get('username','')):return fail('تحقق من الاسم والدور واسم المستخدم (أحرف لاتينية)')
    if old and role!=old['role']:return fail('لا يمكن تغيير دور حساب مرتبط بالسجلات؛ أنشئ حسابًا جديدًا')
    status=d.get('status','active')
    if status not in ['active','paused']:return fail('حالة غير صالحة')
    if old and old['role']=='admin' and status!='active':
      if old['id']==u['id'] or c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]<=1:return fail('لا يمكنك إيقاف حسابك أو آخر مدير')
    pw=str(d.get('password',''))
    if (not old or pw) and len(pw)<10:return fail('كلمة المرور يجب ألا تقل عن 10 أحرف')
    allowed={'admin':['all'],'teacher':['attendance','progress','monthly','quarterly','reports','read_all'],'agent':['reports','finance'],'accountant':['finance']}[role]
    perms=[p for p in d.get('permissions',DEFAULTS[role]) if p in allowed]
    if role=='admin':perms=['all']
    fields=dict(name=d['name'],username=d['username'],role=role,status=status,phone=d.get('phone',''),specialty=d.get('specialty',''),permissions=json.dumps(perms))
    if pw:fields['password']=generate_password_hash(pw)
    if old:c.execute('UPDATE users SET '+','.join(k+'=?' for k in fields)+' WHERE id=?',list(fields.values())+[uid])
    else:uid=c.execute('INSERT INTO users('+','.join(fields)+') VALUES('+','.join('?' for k in fields)+')',list(fields.values())).lastrowid
    audit(c,u,None,'تحديث حساب '+d['username']);return jsonify(id=uid)

@app.route('/api/circles',methods=['GET','POST'])
@app.route('/api/circles/<int:cid>',methods=['PUT','DELETE'])
@secured
def circles(u,cid=None):
 if request.method!='GET' and u['role']!='admin':return fail('للمدير فقط',403)
 with db() as c:
    if request.method=='GET':
      q,a=scope(u);return jsonify(rows(c,f'SELECT c.*,u.name teacher_name,(SELECT COUNT(*) FROM students s WHERE s.circle_id=c.id AND {q}) students_count FROM circles c LEFT JOIN users u ON u.id=c.teacher_id'+('' if u['role'] in ['admin','accountant'] or has(u,'read_all') else ' WHERE c.id IN (SELECT s.circle_id FROM students s WHERE '+q+')'),a+([] if u['role'] in ['admin','accountant'] or has(u,'read_all') else a)))
    if cid and not one(c,'SELECT id FROM circles WHERE id=?',(cid,)):return fail('الحلقة غير موجودة',404)
    if request.method=='DELETE':
      if c.execute('SELECT 1 FROM students WHERE circle_id=?',(cid,)).fetchone():return fail('انقل الطلاب أولًا قبل حذف الحلقة')
      c.execute('UPDATE schedules SET circle_id=NULL WHERE circle_id=?',(cid,));c.execute('DELETE FROM circles WHERE id=?',(cid,));return jsonify(ok=True)
    d=request.json or {};teacher=int(d.get('teacher_id') or 0)
    if not d.get('name') or not one(c,"SELECT id FROM users WHERE id=? AND role='teacher'",(teacher,)):return fail('اسم الحلقة والمعلم مطلوبان')
    v=[d['name'],teacher,d.get('level',''),d.get('schedule','')]
    if cid:c.execute('UPDATE circles SET name=?,teacher_id=?,level=?,schedule=? WHERE id=?',v+[cid])
    else:cid=c.execute('INSERT INTO circles(name,teacher_id,level,schedule) VALUES(?,?,?,?)',v).lastrowid
    audit(c,u,None,'تحديث الحلقة '+d['name']);return jsonify(id=cid)

@app.route('/api/settings',methods=['GET','PUT'])
@secured
def settings(u):
 if u['role']!='admin':return fail('للمدير فقط',403)
 with db() as c:
    if request.method=='PUT':
      d=request.json or {};currency=str(d.get('currency','')).strip();name=str(d.get('institute','')).strip()
      if not currency or len(currency)>12 or not name or len(name)>150:return fail('اسم المعهد والعملة مطلوبان')
      old=c.execute("SELECT value FROM settings WHERE key='currency'").fetchone()[0]
      if old!=currency and not d.get('confirm_currency'):return fail('تغيير العملة يغيّر التسمية فقط ولا يحوّل المبالغ. أكّد أنك تريد إعادة تسمية العملة.')
      for k,v in [('currency',currency),('institute',name)]:c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(k,v))
      audit(c,u,None,'تحديث إعدادات المعهد')
    return jsonify({x['key']:x['value'] for x in rows(c,'SELECT * FROM settings')})

@app.route('/api/schedules',methods=['GET','POST'])
@app.route('/api/schedules/<int:rid>',methods=['DELETE'])
@secured
def schedules(u,rid=None):
 with db() as c:
    if request.method=='GET':
      q,a=scope(u);extra='' if u['role'] in ['admin','accountant'] or has(u,'read_all') else f' WHERE x.circle_id IS NULL OR x.circle_id IN (SELECT s.circle_id FROM students s WHERE {q})'
      return jsonify(rows(c,'SELECT x.*,c.name circle_name FROM schedules x LEFT JOIN circles c ON c.id=x.circle_id'+extra+' ORDER BY date',[] if not extra else a))
    if u['role']!='admin':return fail('للمدير فقط',403)
    if request.method=='DELETE':c.execute('DELETE FROM schedules WHERE id=?',(rid,));return jsonify(ok=True)
    d=request.json or {}
    if not d.get('title') or d.get('type') not in ['monthly','quarterly'] or not valid_date(d.get('date')):return fail('تحقق من بيانات الموعد')
    c.execute('INSERT INTO schedules(title,type,date,circle_id) VALUES(?,?,?,?)',(d['title'],d['type'],d['date'],int(d['circle_id']) if d.get('circle_id') else None));return jsonify(ok=True)

@app.get('/api/dashboard')
@secured
def dashboard(u):
 with db() as c:
    start,end=dates();q,a=scope(u);ss=rows(c,STUDENT_QUERY+' WHERE '+q,a);ids=[s['id'] for s in ss];today=date.today().isoformat();month=today[:7]
    out=dict(students=len(ss),active=sum(s['status']=='active' for s in ss),circles=len(set(s['circle_id'] for s in ss if s['circle_id'])),teachers=len(set(s['teacher_id'] for s in ss if s['teacher_id'])),agents=len(set(s['agent_id'] for s in ss if s['agent_id'])),today=today)
    if u['role']=='admin':
      for key,role in [('teachers','teacher'),('agents','agent')]:out[key]=c.execute('SELECT COUNT(*) FROM users WHERE role=?',(role,)).fetchone()[0]
      out['circles']=c.execute('SELECT COUNT(*) FROM circles').fetchone()[0]
    marks=','.join('?' for _ in ids) or 'NULL'
    if u['role']!='accountant':
      out['attendance']={r['status']:r['n'] for r in rows(c,f'SELECT status,COUNT(*) n FROM attendance WHERE student_id IN ({marks}) AND date=? GROUP BY status',ids+[today])}
      out['monthly_count']=c.execute(f'SELECT COUNT(*) FROM monthly WHERE student_id IN ({marks}) AND substr(date,1,7)=?',ids+[month]).fetchone()[0]
      out['monthly_average']=c.execute(f'SELECT ROUND(AVG(grade),1) FROM monthly WHERE student_id IN ({marks}) AND date BETWEEN ? AND ?',ids+[start,end]).fetchone()[0] or 0
      out['quarterly_average']=c.execute(f'SELECT ROUND(AVG(grade),1) FROM quarterly WHERE student_id IN ({marks}) AND date BETWEEN ? AND ?',ids+[start,end]).fetchone()[0] or 0
      out['trend']=rows(c,f'SELECT substr(date,1,7) month,ROUND(AVG(grade),1) average FROM monthly WHERE student_id IN ({marks}) AND date BETWEEN ? AND ? GROUP BY month ORDER BY month DESC LIMIT 6',ids+[start,end])[::-1]
      out['attendance_week']=rows(c,f'SELECT date,SUM(status IN (\'present\',\'late\')) present,COUNT(*) total FROM attendance WHERE student_id IN ({marks}) AND date>=? GROUP BY date ORDER BY date',ids+[(date.today()-timedelta(days=6)).isoformat()])
    if has(u,'finance'):
      fs=[finance(c,sid,start,end) for sid in ids];out['finance']={k:round(sum(f[k] for f in fs),2) for k in ['charged','paid','balance','overdue','period_paid']}
    out['recent']=rows(c,f'SELECT e.*,s.name student_name FROM events e JOIN students s ON s.id=e.student_id WHERE {q} ORDER BY e.id DESC LIMIT 7',a) if u['role']!='accountant' else []
    return jsonify(out)

@app.get('/api/notifications')
@secured
def notifications(u):
 with db() as c:
    q,a=scope(u);ss=rows(c,'SELECT s.id,s.name FROM students s WHERE '+q,a);result=[];today=date.today().isoformat()
    if u['role']!='accountant':
      for r in rows(c,f"SELECT a.*,s.name FROM attendance a JOIN students s ON s.id=a.student_id WHERE {q} AND a.status='absent' AND a.date=?",a+[today]):result.append(dict(type='absence',title='غياب الطالب '+r['name'],date=today,student_id=r['student_id']))
      for r in rows(c,f'SELECT e.*,s.name FROM events e JOIN students s ON s.id=e.student_id WHERE {q} ORDER BY e.id DESC LIMIT 12',a):result.append(dict(type='update',title=r['name']+' · '+r['action'],date=r['date'][:10],student_id=r['student_id']))
      for r in rows(c,'SELECT * FROM schedules WHERE date BETWEEN ? AND ?',(today,(date.today()+timedelta(days=30)).isoformat())):
        if r['circle_id'] is None or c.execute('SELECT 1 FROM students s WHERE '+q+' AND s.circle_id=?',a+[r['circle_id']]).fetchone():result.append(dict(type='exam',title=r['title'],date=r['date']))
    if has(u,'finance'):
      for s in ss:
        f=finance(c,s['id'])
        if f['overdue']>0:result.append(dict(type='fee',title='رسوم متأخرة · '+s['name'],amount=f['overdue'],date=today,student_id=s['id']))
    return jsonify(result)

@app.get('/api/reports/<int:sid>')
@secured
def report(u,sid):
 if not has(u,'reports') and not has(u,'finance'):return fail('ليست لديك صلاحية استخراج التقارير',403)
 return student_detail.__wrapped__(u,sid)

@app.get('/api/receipts/<int:rid>')
@secured
def receipt(u,rid):
 if not has(u,'finance'):return fail('ليست لديك صلاحية مالية',403)
 with db() as c:
    r=one(c,'SELECT p.*,s.name,s.code,u.name author FROM payments p JOIN students s ON s.id=p.student_id LEFT JOIN users u ON u.id=p.created_by WHERE p.id=?',(rid,))
    if not r or not access(c,u,r['student_id']):return fail('الإيصال غير موجود أو خارج صلاحياتك',404)
    r['amount']/=100;return jsonify(r)


@app.route('/api/report-archive',methods=['GET','POST'])
@app.get('/api/report-archive/<int:rid>')
@secured
def report_archive(u,rid=None):
 if not has(u,'reports') and not has(u,'finance'):return fail('ليست لديك صلاحية التقارير',403)
 if request.method=='POST':
    sid=int((request.json or {}).get('student_id') or 0);start,end=dates()
    response=student_detail.__wrapped__(u,sid)
    if isinstance(response,tuple):return response
    payload=response.get_json()
    with db() as c:
      rid=c.execute('INSERT INTO report_archive(student_id,created_by,created_at,start,end,payload) VALUES(?,?,?,?,?,?)',(sid,u['id'],datetime.now().isoformat(timespec='seconds'),start,end,json.dumps(payload,ensure_ascii=False))).lastrowid
      audit(c,u,sid,'حفظ نسخة تقرير في الأرشيف')
    return jsonify(id=rid)
 with db() as c:
    if rid:
      r=one(c,'SELECT * FROM report_archive WHERE id=?',(rid,))
      if not r or not access(c,u,r['student_id']):return fail('التقرير غير متاح أو خارج صلاحياتك',404)
      payload=json.loads(r.pop('payload'))
      if not has(u,'finance'):
        payload.pop('finance',None)
        for k in ['charges','payments']:payload['records'].pop(k,None)
      if u['role']=='accountant':
        payload['records']={k:v for k,v in payload['records'].items() if k in ['charges','payments']};payload['events']=[]
        for k in ['notes','guardian','guardian_phone','birth_date']:payload['student'].pop(k,None)
      r['data']=payload;return jsonify(r)
    q,a=scope(u);extra=''
    if request.args.get('student'):extra=' AND s.id=?';a.append(request.args['student'])
    result=rows(c,'SELECT r.id,r.student_id,r.created_at,r.start,r.end,s.name student_name,u.name author FROM report_archive r JOIN students s ON s.id=r.student_id LEFT JOIN users u ON u.id=r.created_by WHERE '+q+extra+' ORDER BY r.id DESC',a)
    return jsonify(result)


@app.get('/api/backup')
@secured
def backup_download(u):
    if u['role']!='admin':return fail('هذه العملية للمدير فقط',403)
    ts=datetime.now().strftime('%Y%m%d-%H%M%S')
    path=os.path.join(ROOT,'data',f'qalun-backup-{ts}.sqlite3')
    with db() as c:
        src=sqlite3.connect(DB);dst=sqlite3.connect(path)
        with dst:src.backup(dst)
        src.close();dst.close()
        audit(c,u,None,'تنزيل نسخة احتياطية من قاعدة البيانات')
    return send_file(path,as_attachment=True,download_name=f'qalun-backup-{ts}.sqlite3')

@app.post('/api/restore')
@secured
def restore_db(u):
    if u['role']!='admin':return fail('هذه العملية للمدير فقط',403)
    f=request.files.get('file')
    if not f or not f.filename.lower().endswith('.sqlite3'):return fail('ارفع ملف النسخة الاحتياطية بصيغة .sqlite3')
    data=f.read()
    if not data or len(data)>50*1024*1024 or not data.startswith(b'SQLite format 3'):return fail('الملف المرفوع ليس قاعدة بيانات SQLite صالحة')
    dbdir=os.path.dirname(DB) or '.'
    tmp=os.path.join(dbdir,'.qalun-restore.tmp')
    with open(tmp,'wb') as out:out.write(data)
    def cleanup():
        for pth in (tmp,DB+'-wal',DB+'-shm'):
            if os.path.exists(pth):
                try:os.remove(pth)
                except OSError:pass
    try:
        chk=sqlite3.connect(tmp)
        try:
            tables={r[0] for r in chk.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'users','students','settings'}.issubset(tables) or chk.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError
        finally:chk.close()
        ts=datetime.now().strftime('%Y%m%d-%H%M%S')
        pre=os.path.join(dbdir,f'pre-restore-{ts}.sqlite3')
        src=sqlite3.connect(DB);dst=sqlite3.connect(pre)
        with dst:src.backup(dst)
        src.close();dst.close()
        for suf in ('-wal','-shm'):
            pth=DB+suf
            if os.path.exists(pth):os.remove(pth)
        os.replace(tmp,DB)
        with db() as c:audit(c,u,None,'استعادة قاعدة البيانات من نسخة احتياطية')
        return jsonify(ok=True)
    except ValueError:
        cleanup();return fail('النسخة المرفوعة غير صالحة أو تالفة؛ لم يتم تغيير أي بيانات',400)
    except Exception:
        cleanup()
        raise

@app.post('/api/demo-reset')
@secured
def demo_reset(u):
    if u['role']!='admin':return fail('هذه العملية للمدير فقط',403)
    with db() as c:
        c.execute("UPDATE settings SET value='0' WHERE key='demo'")
        for t in ['report_archive','events','payments','charges','quarterly','monthly','progress','attendance','students','circles','schedules']:
            c.execute(f'DELETE FROM {t}')
        try:c.execute("DELETE FROM sqlite_sequence WHERE name='students'")
        except sqlite3.OperationalError:pass
        audit(c,u,None,'بدء العمل الفعلي: مسح جميع البيانات التجريبية')
    return jsonify(ok=True)


def parse_import_csv(raw):
    text=raw.decode('utf-8-sig',errors='replace')
    reader=csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:raise ValueError('الملف فارغ أو لا يحتوي على رؤوس الأعمدة')
    def norm(h):return (h or '').strip().replace('  ',' ')
    aliases={'name':['الاسم الكامل','الاسم','اسم الطالب','name'],'birth_date':['تاريخ الميلاد','date_of_birth'],'phone':['رقم الهاتف','الهاتف','phone'],'guardian':['اسم ولي الأمر','ولي الأمر','guardian'],'guardian_phone':['هاتف ولي الأمر','هاتف وليّ الأمر','guardian_phone'],'circle':['الحلقة','circle'],'agent':['الوكيل','الوكيل المسؤول','agent'],'level':['المستوى','level'],'status':['الحالة','status']}
    col={}
    for h in reader.fieldnames:
        n=norm(h)
        for std,opts in aliases.items():
            if n in opts:col[std]=h;break
    if 'name' not in col:raise ValueError('لا توجد عمود «الاسم الكامل» — نزّل القالب النموذجي واملأه بنفس الأعمدة')
    rows=[]
    for i,r in enumerate(reader,start=2):
        row={k:(r.get(v) or '').strip() for k,v in col.items()}
        if any(x for x in row.values()):rows.append((i,row))
    return rows

@app.post('/api/students/import')
@secured
def import_students(u):
    if u['role']!='admin':return fail('هذه العملية للمدير فقط',403)
    f=request.files.get('file')
    if not f:return fail('ارفع ملف CSV')
    if not f.filename.lower().endswith('.csv'):return fail('الملف يجب أن يكون بصيغة CSV (تصدير من Excel أو Google Sheets)')
    raw=f.read()
    if len(raw)>5*1024*1024:return fail('حجم الملف أكبر من 5 ميغابايت')
    try:entries=parse_import_csv(raw)
    except ValueError as e:return fail(str(e))
    if not entries:return fail('لا توجد صفوف بيانات في الملف (بعد رأس العمود)')
    if len(entries)>2000:return fail('الحد الأقصى 2000 طالب في استيراد واحد')
    with db() as c:
        circles={x['name'].strip().lower():x['id'] for x in rows(c,'SELECT id,name FROM circles')}
        agents={x['name'].strip().lower():x['id'] for x in rows(c,"SELECT id,name FROM users WHERE role='agent'")}
        existing={x['name'].strip() for x in rows(c,'SELECT name FROM students')}
        added=0;errors=[];seen=set()
        for i,row in entries:
            name=row.get('name','').strip()
            if not name or len(name)>120:errors.append((i,'الاسم الكامل مطلوب (حتى 120 حرفًا)'));continue
            if name in existing or name in seen:
                errors.append((i,'اسم الطالب مكرر (في الملف أو في النظام)'));continue
            seen.add(name)
            birth=row.get('birth_date','')
            if birth and (not valid_date(birth) or birth>date.today().isoformat()):errors.append((i,'تاريخ الميلاد غير صالح (YYYY-MM-DD)'));continue
            circle=row.get('circle','')
            cid=circles.get(circle.strip().lower()) if circle else None
            if circle and cid is None:errors.append((i,'الحلقة غير موجودة: '+circle));continue
            agent=row.get('agent','')
            aid=agents.get(agent.strip().lower()) if agent else None
            if agent and aid is None:errors.append((i,'الوكيل غير موجود: '+agent));continue
            level=row.get('level','')
            if level and level not in ['مبتدئ','متوسط','متقدم']:errors.append((i,'المستوى يجب أن يكون: مبتدئ / متوسط / متقدم'));continue
            status=row.get('status','')
            if status:
                status={'نشط':'active','موقوف':'paused','متخرج':'graduated'}.get(status)
                if not status:errors.append((i,'الحالة يجب أن تكون: نشط / موقوف / متخرج'));continue
            else:status='active'
            sid=c.execute("INSERT INTO students(name,birth_date,phone,guardian,guardian_phone,registered,circle_id,agent_id,level,status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (name,birth,row.get('phone',''),row.get('guardian',''),row.get('guardian_phone',''),date.today().isoformat(),cid,aid,level,status)).lastrowid
            c.execute('UPDATE students SET code=? WHERE id=?',(f'QL-{sid:04}',sid))
            audit(c,u,sid,'إضافة طالب عن طريق الاستيراد الجماعي')
            added+=1
        return jsonify(added=added,errors=[{'row':i,'message':m} for i,m in errors])

init_db()
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT',3001)),debug=False)
