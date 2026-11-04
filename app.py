import os, sqlite3, secrets, hashlib, hmac, json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, render_template

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','false').lower()=='true')
DB = os.environ.get('DB_PATH', '/data/coffeepos.db')

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

@app.get('/')
def home(): return render_template('index.html')

@app.post('/api/login')
def login():
    body=request.get_json(silent=True) or {}; name=body.get('name',''); pin=str(body.get('pin',''))
    if len(pin)!=4 or not pin.isdigit(): return jsonify(error='Invalid credentials'),401
    with db() as c: user=c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
    if not user or not verify_pin(pin,user['pin_hash']): return jsonify(error='Invalid credentials'),401
    session.clear();session.update(uid=user['id'],name=user['name'],role=user['role'])
    return jsonify(name=user['name'],role=user['role'])

@app.post('/api/logout')
def logout(): session.clear();return jsonify(ok=True)

@app.get('/api/users')
def users():
    with db() as c: return jsonify([dict(r) for r in c.execute('SELECT id,name FROM users ORDER BY name')])

@app.post('/api/users')
@admin
def add_user():
    b=request.get_json(silent=True) or {}; pin=str(b.get('pin',''));name=str(b.get('name','')).strip();role=b.get('role','customer')
    if not name or len(pin)!=4 or not pin.isdigit() or role not in ('customer','admin'):return jsonify(error='Invalid user'),400
    try:
        with db() as c: c.execute('INSERT INTO users(name,pin_hash,role) VALUES(?,?,?)',(name,pin_hash(pin),role))
    except sqlite3.IntegrityError: return jsonify(error='Name already used'),409
    return jsonify(ok=True),201

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
        records=[dict(r) for r in c.execute('SELECT * FROM orders ORDER BY id DESC LIMIT 100')]
        for o in records:o['lines']=[dict(r) for r in c.execute('SELECT * FROM order_lines WHERE order_id=?',(o['id'],))]
    return jsonify(records)

@app.patch('/api/orders/<int:oid>')
@admin
def status(oid):
    status=(request.get_json(silent=True) or {}).get('status')
    if status not in ('new','preparing','ready','completed','canceled'):return jsonify(error='Invalid status'),400
    with db() as c:c.execute('UPDATE orders SET status=? WHERE id=?',(status,oid))
    return jsonify(ok=True)

@app.get('/api/health')
def health():return jsonify(status='ok')

# Print jobs are queued, not dispatched; hardware integration pending.
init()
