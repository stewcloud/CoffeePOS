import os, sqlite3, secrets, hashlib, hmac, json, time
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','false').lower()=='true',
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
    MAX_CONTENT_LENGTH=64 * 1024,
)
DB = os.environ.get('DB_PATH', '/data/coffeepos.db')
LOGIN_ATTEMPTS = {}

def db():
    os.makedirs(os.path.dirname(DB) or '.', exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def pin_hash(pin, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + '$' + hashlib.pbkdf2_hmac('sha256', pin.encode(), bytes.fromhex(salt), 250000).hex()

def verify_pin(pin, stored):
    try:
        salt, digest = stored.split('$',1)
        return hmac.compare_digest(pin_hash(pin,salt).split('$')[1], digest)
    except Exception: return False

def valid_pin(pin): return len(pin) == 4 and pin.isdigit()

def client_ip(): return request.headers.get('CF-Connecting-IP') or request.remote_addr or 'unknown'

def login_allowed(ip):
    now=time.time(); attempts=[t for t in LOGIN_ATTEMPTS.get(ip,[]) if now-t < 300]
    LOGIN_ATTEMPTS[ip]=attempts
    return len(attempts) < 10

def login_failed(ip): LOGIN_ATTEMPTS.setdefault(ip,[]).append(time.time())

def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, pin_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer');
        CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL, sort_order INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, category_id INTEGER REFERENCES categories(id), name TEXT NOT NULL, description TEXT DEFAULT '', image_url TEXT DEFAULT '', available INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), customer TEXT NOT NULL, to_go INTEGER NOT NULL, notes TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS order_lines(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), item_id INTEGER, name TEXT NOT NULL, quantity INTEGER NOT NULL, modifiers TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS print_jobs(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), printer TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, error TEXT DEFAULT '');
        """)
        if not c.execute('SELECT 1 FROM users').fetchone():
            pin=os.environ.get('ADMIN_PIN')
            if not pin or len(pin)!=4 or not pin.isdigit(): raise RuntimeError('Set a 4-digit ADMIN_PIN')
            c.execute('INSERT INTO users(name,pin_hash,role) VALUES(?,?,?)', ('Admin',pin_hash(pin),'admin'))
        if not c.execute('SELECT 1 FROM categories').fetchone():
            c.execute('INSERT INTO categories(name) VALUES(?)',('Coffee',))
            c.execute('INSERT INTO items(category_id,name,description) VALUES(1,?,?)',('Latte','Espresso and milk'))

def auth(fn):
    @wraps(fn)
    def inner(*a,**kw):
        if not session.get('uid'): return jsonify(error='Authentication required'),401
        return fn(*a,**kw)
    return inner

def admin(fn):
    @wraps(fn)
    @auth
    def inner(*a,**kw):
        if session.get('role')!='admin': return jsonify(error='Admin only'),403
        return fn(*a,**kw)
    return inner

@app.before_request
def csrf_protect():
    if request.method in ('POST','PATCH','DELETE') and request.endpoint not in ('login',):
        if session.get('uid') and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''), session.get('csrf','')):
            return jsonify(error='Invalid security token; refresh and try again'),403

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    response.headers['Cache-Control']='no-store'
    return response

@app.get('/')
def home(): return render_template('index.html')

@app.post('/api/login')
def login():
    body=request.get_json(silent=True) or {}; name=body.get('name',''); pin=str(body.get('pin',''))
    ip=client_ip()
    if not login_allowed(ip): return jsonify(error='Too many attempts. Try again in five minutes.'),429
    if not valid_pin(pin): login_failed(ip); return jsonify(error='Invalid credentials'),401
    with db() as c: user=c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
    if not user or not verify_pin(pin,user['pin_hash']): login_failed(ip); return jsonify(error='Invalid credentials'),401
    LOGIN_ATTEMPTS.pop(ip,None)
    session.clear();session.permanent=True;session.update(uid=user['id'],name=user['name'],role=user['role'],csrf=secrets.token_urlsafe(24))
    return jsonify(id=user['id'],name=user['name'],role=user['role'],csrf=session['csrf'])

@app.post('/api/logout')
def logout(): session.clear();return jsonify(ok=True)

@app.get('/api/users')
def users():
    with db() as c: return jsonify([dict(r) for r in c.execute('SELECT id,name FROM users ORDER BY name')])

@app.get('/api/admin/users')
@admin
def admin_users():
    with db() as c: return jsonify([dict(r) for r in c.execute('SELECT id,name,role FROM users ORDER BY name COLLATE NOCASE')])

@app.post('/api/users')
@admin
def add_user():
    b=request.get_json(silent=True) or {}; pin=str(b.get('pin',''));name=str(b.get('name','')).strip();role=b.get('role','customer')
    if not name or len(name)>50 or not valid_pin(pin) or role not in ('customer','admin'):return jsonify(error='Enter a name, role, and 4-digit PIN'),400
    try:
        with db() as c: c.execute('INSERT INTO users(name,pin_hash,role) VALUES(?,?,?)',(name,pin_hash(pin),role))
    except sqlite3.IntegrityError: return jsonify(error='Name already used'),409
    return jsonify(ok=True),201

@app.patch('/api/users/<int:user_id>')
@admin
def update_user(user_id):
    b=request.get_json(silent=True) or {}; name=str(b.get('name','')).strip(); role=b.get('role'); pin=str(b.get('pin','')).strip()
    if not name or len(name)>50 or role not in ('customer','admin') or (pin and not valid_pin(pin)):
        return jsonify(error='Enter a name, role, and optional 4-digit PIN'),400
    with db() as c:
        current=c.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not current:return jsonify(error='User not found'),404
        if current['role']=='admin' and role!='admin' and c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] <= 1:
            return jsonify(error='CoffeePOS must keep at least one admin'),409
        try:
            if pin:c.execute('UPDATE users SET name=?,role=?,pin_hash=? WHERE id=?',(name,role,pin_hash(pin),user_id))
            else:c.execute('UPDATE users SET name=?,role=? WHERE id=?',(name,role,user_id))
        except sqlite3.IntegrityError:return jsonify(error='Name already used'),409
    if session['uid']==user_id:session.update(name=name,role=role)
    return jsonify(ok=True)

@app.delete('/api/users/<int:user_id>')
@admin
def delete_user(user_id):
    if session['uid']==user_id:return jsonify(error='You cannot delete your signed-in account'),409
    with db() as c:
        current=c.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        if not current:return jsonify(error='User not found'),404
        if current['role']=='admin' and c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] <= 1:
            return jsonify(error='CoffeePOS must keep at least one admin'),409
        c.execute('UPDATE orders SET user_id=NULL WHERE user_id=?',(user_id,))
        c.execute('DELETE FROM users WHERE id=?',(user_id,))
    return jsonify(ok=True)

@app.post('/api/change-pin')
@auth
def change_pin():
    b=request.get_json(silent=True) or {}; current=str(b.get('current_pin','')); new=str(b.get('new_pin',''))
    if not valid_pin(new):return jsonify(error='New PIN must be four digits'),400
    with db() as c:
        user=c.execute('SELECT pin_hash FROM users WHERE id=?',(session['uid'],)).fetchone()
        if not user or not verify_pin(current,user['pin_hash']):return jsonify(error='Current PIN is incorrect'),401
        c.execute('UPDATE users SET pin_hash=? WHERE id=?',(pin_hash(new),session['uid']))
    return jsonify(ok=True)

@app.get('/api/menu')
@auth
def menu():
    with db() as c:
        return jsonify(categories=[dict(x) for x in c.execute('SELECT * FROM categories ORDER BY sort_order,id')],items=[dict(x) for x in c.execute('SELECT * FROM items ORDER BY id')])

@app.post('/api/categories')
@admin
def category():
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip()
    if not name:return jsonify(error='Name required'),400
    with db() as c: c.execute('INSERT INTO categories(name) VALUES(?)',(name,))
    return jsonify(ok=True),201

@app.patch('/api/categories/<int:category_id>')
@admin
def update_category(category_id):
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip();sort_order=b.get('sort_order',0)
    if not name:return jsonify(error='Name required'),400
    with db() as c:
        cur=c.execute('UPDATE categories SET name=?,sort_order=? WHERE id=?',(name,int(sort_order),category_id))
        if not cur.rowcount:return jsonify(error='Category not found'),404
    return jsonify(ok=True)

@app.delete('/api/categories/<int:category_id>')
@admin
def delete_category(category_id):
    with db() as c:
        if c.execute('SELECT 1 FROM items WHERE category_id=?',(category_id,)).fetchone():return jsonify(error='Move or delete items in this category first'),409
        cur=c.execute('DELETE FROM categories WHERE id=?',(category_id,))
        if not cur.rowcount:return jsonify(error='Category not found'),404
    return jsonify(ok=True)

@app.post('/api/items')
@admin
def add_item():
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip()
    if not name:return jsonify(error='Name required'),400
    with db() as c: c.execute('INSERT INTO items(category_id,name,description,image_url) VALUES(?,?,?,?)',(b.get('category_id'),name,b.get('description',''),b.get('image_url','')))
    return jsonify(ok=True),201

@app.patch('/api/items/<int:item_id>')
@admin
def update_item(item_id):
    b=request.get_json(silent=True) or {};allowed=('name','description','image_url','available','category_id')
    changes={k:v for k,v in b.items() if k in allowed}
    if not changes:return jsonify(error='No changes'),400
    with db() as c:
        cur=c.execute('UPDATE items SET '+','.join(k+'=?' for k in changes)+' WHERE id=?',(*changes.values(),item_id))
        if not cur.rowcount:return jsonify(error='Not found'),404
    return jsonify(ok=True)

@app.delete('/api/items/<int:item_id>')
@admin
def delete_item(item_id):
    with db() as c:
        cur=c.execute('DELETE FROM items WHERE id=?',(item_id,))
        if not cur.rowcount:return jsonify(error='Item not found'),404
    return jsonify(ok=True)

@app.post('/api/orders')
@auth
def order():
    b=request.get_json(silent=True) or {};lines=b.get('lines',[])
    if not isinstance(lines,list) or not lines or len(lines)>30:return jsonify(error='Add 1-30 items'),400
    try:
        with db() as c:
            resolved=[]
            for line in lines:
                item=c.execute('SELECT * FROM items WHERE id=? AND available=1',(int(line['item_id']),)).fetchone()
                qty=int(line.get('quantity',1))
                if not item or not 1<=qty<=20:raise ValueError('Unavailable item or invalid quantity')
                mods=line.get('modifiers',{})
                if not isinstance(mods,dict) or len(json.dumps(mods))>2000:raise ValueError('Invalid modifiers')
                resolved.append((item,qty,mods))
            cur=c.execute('INSERT INTO orders(user_id,customer,to_go,notes,created_at) VALUES(?,?,?,?,?)',(session['uid'],session['name'],int(bool(b.get('to_go',False))),str(b.get('notes',''))[:500],datetime.now(timezone.utc).isoformat()))
            oid=cur.lastrowid
            for item,qty,mods in resolved:c.execute('INSERT INTO order_lines(order_id,item_id,name,quantity,modifiers) VALUES(?,?,?,?,?)',(oid,item['id'],item['name'],qty,json.dumps(mods)))
            c.execute('INSERT INTO print_jobs(order_id,printer) VALUES(?,?)',(oid,'epson'))
            if b.get('to_go'):c.execute('INSERT INTO print_jobs(order_id,printer) VALUES(?,?)',(oid,'brother'))
        return jsonify(id=oid,status='new'),201
    except (ValueError,KeyError,TypeError) as e:return jsonify(error=str(e)),400

@app.get('/api/orders')
@auth
def orders():
    with db() as c:
        if session.get('role')=='admin': rows=c.execute('SELECT * FROM orders ORDER BY id DESC LIMIT 100')
        else: rows=c.execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100',(session['uid'],))
        records=[dict(r) for r in rows]
        for o in records:o['lines']=[dict(r) for r in c.execute('SELECT * FROM order_lines WHERE order_id=?',(o['id'],))]
    return jsonify(records)

@app.patch('/api/orders/<int:oid>')
@admin
def status(oid):
    status=(request.get_json(silent=True) or {}).get('status')
    if status not in ('new','preparing','ready','completed','canceled'):return jsonify(error='Invalid status'),400
    with db() as c:
        cur=c.execute('UPDATE orders SET status=? WHERE id=?',(status,oid))
        if not cur.rowcount:return jsonify(error='Order not found'),404
    return jsonify(ok=True)

@app.get('/api/health')
def health():return jsonify(status='ok')

# Print jobs are queued, not dispatched; hardware integration pending.
init()
