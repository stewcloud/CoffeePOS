import os, sqlite3, secrets, hashlib, hmac, json, time, socket, threading, textwrap
from urllib import request as urlrequest, parse as urlparse
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image, ImageDraw, ImageFont
from brother_ql.raster import BrotherQLRaster
from brother_ql.conversion import convert as brother_convert

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
PRINT_MODE = os.environ.get('PRINT_MODE','mock').lower()
EPSON_HOST = os.environ.get('EPSON_HOST','')
EPSON_PORT = int(os.environ.get('EPSON_PORT','9100'))
CHIT_COLUMNS = int(os.environ.get('CHIT_COLUMNS','32'))
BROTHER_HOST = os.environ.get('BROTHER_HOST','192.168.1.156')
BROTHER_PORT = int(os.environ.get('BROTHER_PORT','9100'))
BROTHER_MODEL = os.environ.get('BROTHER_MODEL','QL-820NWB')
BROTHER_LABEL_SIZE = os.environ.get('BROTHER_LABEL_SIZE','62')

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

def pin_owner(pin, exclude_id=None):
    with db() as c: rows=c.execute('SELECT id,pin_hash FROM users').fetchall()
    return next((r['id'] for r in rows if r['id'] != exclude_id and verify_pin(pin,r['pin_hash'])),None)

def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, pin_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer');
        CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT NOT NULL, sort_order INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, category_id INTEGER REFERENCES categories(id), name TEXT NOT NULL, description TEXT DEFAULT '', image_url TEXT DEFAULT '', available INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), customer TEXT NOT NULL, to_go INTEGER NOT NULL, notes TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS order_lines(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), item_id INTEGER, name TEXT NOT NULL, quantity INTEGER NOT NULL, modifiers TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS print_jobs(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), printer TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, error TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS sections(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, sort_order INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS modifier_groups(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, min_select INTEGER NOT NULL DEFAULT 0, max_select INTEGER NOT NULL DEFAULT 1, required INTEGER NOT NULL DEFAULT 0, sort_order INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS modifier_options(id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES modifier_groups(id) ON DELETE CASCADE, name TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, UNIQUE(group_id,name));
        CREATE TABLE IF NOT EXISTS item_modifier_groups(item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE, group_id INTEGER NOT NULL REFERENCES modifier_groups(id) ON DELETE CASCADE, PRIMARY KEY(item_id,group_id));
        """)
        columns={r['name'] for r in c.execute('PRAGMA table_info(items)')}
        if 'section_id' not in columns:c.execute('ALTER TABLE items ADD COLUMN section_id INTEGER REFERENCES sections(id)')
        c.execute("UPDATE print_jobs SET status='archived',error='Legacy pre-v0.3 queue entry' WHERE status='pending' AND printer IN ('epson','brother')")
        if not c.execute('SELECT 1 FROM sections').fetchone():c.execute('INSERT INTO sections(name) VALUES(?)',('Coffee Bar',))
        c.execute('UPDATE items SET section_id=(SELECT id FROM sections ORDER BY id LIMIT 1) WHERE section_id IS NULL')
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
    body=request.get_json(silent=True) or {}; pin=str(body.get('pin',''))
    ip=client_ip()
    if not login_allowed(ip): return jsonify(error='Too many attempts. Try again in five minutes.'),429
    if not valid_pin(pin): login_failed(ip); return jsonify(error='Invalid credentials'),401
    with db() as c: users=c.execute('SELECT * FROM users ORDER BY id').fetchall()
    user=next((u for u in users if verify_pin(pin,u['pin_hash'])),None)
    if not user: login_failed(ip); return jsonify(error='Invalid credentials'),401
    LOGIN_ATTEMPTS.pop(ip,None)
    session.clear();session.permanent=True;session.update(uid=user['id'],name=user['name'],role=user['role'],csrf=secrets.token_urlsafe(24))
    return jsonify(id=user['id'],name=user['name'],role=user['role'],csrf=session['csrf'])

@app.post('/api/logout')
def logout(): session.clear();return jsonify(ok=True)

@app.get('/api/users')
@auth
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
    if pin_owner(pin):return jsonify(error='That PIN is already assigned to another user'),409
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
    if pin and pin_owner(pin,user_id):return jsonify(error='That PIN is already assigned to another user'),409
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
    if pin_owner(new,session['uid']):return jsonify(error='That PIN is already assigned to another user'),409
    with db() as c:
        user=c.execute('SELECT pin_hash FROM users WHERE id=?',(session['uid'],)).fetchone()
        if not user or not verify_pin(current,user['pin_hash']):return jsonify(error='Current PIN is incorrect'),401
        c.execute('UPDATE users SET pin_hash=? WHERE id=?',(pin_hash(new),session['uid']))
    return jsonify(ok=True)

@app.get('/api/menu')
@auth
def menu():
    with db() as c:
        groups=[dict(x) for x in c.execute('SELECT * FROM modifier_groups ORDER BY sort_order,id')]
        for g in groups:g['options']=[dict(x) for x in c.execute('SELECT * FROM modifier_options WHERE group_id=? ORDER BY sort_order,id',(g['id'],))]
        items=[dict(x) for x in c.execute('SELECT * FROM items ORDER BY id')]
        for i in items:i['modifier_group_ids']=[r[0] for r in c.execute('SELECT group_id FROM item_modifier_groups WHERE item_id=?',(i['id'],))]
        return jsonify(sections=[dict(x) for x in c.execute('SELECT * FROM sections ORDER BY sort_order,id')],categories=[dict(x) for x in c.execute('SELECT * FROM categories ORDER BY sort_order,id')],items=items,modifier_groups=groups)

@app.post('/api/sections')
@admin
def add_section():
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip()
    if not name:return jsonify(error='Name required'),400
    try:
        with db() as c:c.execute('INSERT INTO sections(name,sort_order) VALUES(?,?)',(name,int(b.get('sort_order',0))))
    except sqlite3.IntegrityError:return jsonify(error='Section name already used'),409
    return jsonify(ok=True),201

@app.patch('/api/sections/<int:section_id>')
@admin
def update_section(section_id):
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip()
    if not name:return jsonify(error='Name required'),400
    with db() as c:c.execute('UPDATE sections SET name=?,sort_order=? WHERE id=?',(name,int(b.get('sort_order',0)),section_id))
    return jsonify(ok=True)

@app.delete('/api/sections/<int:section_id>')
@admin
def delete_section(section_id):
    with db() as c:
        if c.execute('SELECT 1 FROM items WHERE section_id=?',(section_id,)).fetchone():return jsonify(error='Move or delete items in this section first'),409
        c.execute('DELETE FROM sections WHERE id=?',(section_id,))
    return jsonify(ok=True)

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
    with db() as c: c.execute('INSERT INTO items(category_id,section_id,name,description,image_url) VALUES(?,?,?,?,?)',(b.get('category_id'),b.get('section_id'),name,b.get('description',''),b.get('image_url','')))
    return jsonify(ok=True),201

@app.patch('/api/items/<int:item_id>')
@admin
def update_item(item_id):
    b=request.get_json(silent=True) or {};allowed=('name','description','image_url','available','category_id','section_id')
    changes={k:v for k,v in b.items() if k in allowed}
    if not changes:return jsonify(error='No changes'),400
    with db() as c:
        cur=c.execute('UPDATE items SET '+','.join(k+'=?' for k in changes)+' WHERE id=?',(*changes.values(),item_id))
        if not cur.rowcount:return jsonify(error='Not found'),404
    return jsonify(ok=True)

@app.post('/api/modifier-groups')
@admin
def add_modifier_group():
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip();mx=int(b.get('max_select',1));mn=int(b.get('min_select',0))
    if not name or mn<0 or mx<1 or mn>mx:return jsonify(error='Invalid modifier group'),400
    try:
        with db() as c:c.execute('INSERT INTO modifier_groups(name,min_select,max_select,required) VALUES(?,?,?,?)',(name,mn,mx,int(bool(b.get('required')))))
    except sqlite3.IntegrityError:return jsonify(error='Group name already used'),409
    return jsonify(ok=True),201

@app.patch('/api/modifier-groups/<int:group_id>')
@admin
def update_modifier_group(group_id):
    b=request.get_json(silent=True) or {};name=str(b.get('name','')).strip();mx=int(b.get('max_select',1));mn=int(b.get('min_select',0))
    if not name or mn<0 or mx<1 or mn>mx:return jsonify(error='Invalid modifier group'),400
    with db() as c:c.execute('UPDATE modifier_groups SET name=?,min_select=?,max_select=?,required=? WHERE id=?',(name,mn,mx,int(bool(b.get('required'))),group_id))
    return jsonify(ok=True)

@app.delete('/api/modifier-groups/<int:group_id>')
@admin
def delete_modifier_group(group_id):
    with db() as c:c.execute('DELETE FROM modifier_groups WHERE id=?',(group_id,))
    return jsonify(ok=True)

@app.post('/api/modifier-groups/<int:group_id>/options')
@admin
def add_modifier_option(group_id):
    name=str((request.get_json(silent=True) or {}).get('name','')).strip()
    if not name:return jsonify(error='Name required'),400
    try:
        with db() as c:c.execute('INSERT INTO modifier_options(group_id,name) VALUES(?,?)',(group_id,name))
    except sqlite3.IntegrityError:return jsonify(error='Option already exists'),409
    return jsonify(ok=True),201

@app.delete('/api/modifier-options/<int:option_id>')
@admin
def delete_modifier_option(option_id):
    with db() as c:c.execute('DELETE FROM modifier_options WHERE id=?',(option_id,))
    return jsonify(ok=True)

@app.patch('/api/modifier-options/<int:option_id>')
@admin
def update_modifier_option(option_id):
    name=str((request.get_json(silent=True) or {}).get('name','')).strip()
    if not name:return jsonify(error='Name required'),400
    try:
        with db() as c:c.execute('UPDATE modifier_options SET name=? WHERE id=?',(name,option_id))
    except sqlite3.IntegrityError:return jsonify(error='Option already exists'),409
    return jsonify(ok=True)

@app.put('/api/items/<int:item_id>/modifier-groups')
@admin
def set_item_modifier_groups(item_id):
    ids=(request.get_json(silent=True) or {}).get('group_ids',[])
    if not isinstance(ids,list):return jsonify(error='group_ids must be a list'),400
    with db() as c:
        c.execute('DELETE FROM item_modifier_groups WHERE item_id=?',(item_id,))
        for gid in set(map(int,ids)):c.execute('INSERT INTO item_modifier_groups(item_id,group_id) VALUES(?,?)',(item_id,gid))
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
                resolved_mods={}
                assigned={r[0] for r in c.execute('SELECT group_id FROM item_modifier_groups WHERE item_id=?',(item['id'],))}
                for gid in assigned:
                    group=c.execute('SELECT * FROM modifier_groups WHERE id=?',(gid,)).fetchone(); selected=mods.get(str(gid),mods.get(gid,[]))
                    if not isinstance(selected,list):raise ValueError('Invalid modifier selection')
                    selected=list(dict.fromkeys(map(int,selected)))
                    minimum=max(group['min_select'],1 if group['required'] else 0)
                    if not minimum<=len(selected)<=group['max_select']:raise ValueError(f"Choose {minimum}-{group['max_select']} for {group['name']}")
                    if selected:
                        placeholders=','.join('?' for _ in selected)
                        names=[r[0] for r in c.execute(f'SELECT name FROM modifier_options WHERE group_id=? AND id IN ({placeholders})',(gid,*selected))]
                        if len(names)!=len(selected):raise ValueError('Invalid modifier option')
                        resolved_mods[group['name']]=names
                unknown=set(map(int,mods.keys()))-assigned if mods else set()
                if unknown:raise ValueError('Modifier group not assigned to item')
                resolved.append((item,qty,resolved_mods))
            cur=c.execute('INSERT INTO orders(user_id,customer,to_go,notes,created_at) VALUES(?,?,?,?,?)',(session['uid'],session['name'],int(bool(b.get('to_go',False))),str(b.get('notes',''))[:500],datetime.now(timezone.utc).isoformat()))
            oid=cur.lastrowid
            for item,qty,mods in resolved:c.execute('INSERT INTO order_lines(order_id,item_id,name,quantity,modifiers) VALUES(?,?,?,?,?)',(oid,item['id'],item['name'],qty,json.dumps(mods)))
            c.execute('INSERT INTO print_jobs(order_id,printer) VALUES(?,?)',(oid,'chit'))
            if b.get('to_go'):c.execute('INSERT INTO print_jobs(order_id,printer) VALUES(?,?)',(oid,'label'))
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

def order_payload(order_id):
    with db() as c:
        order=dict(c.execute('SELECT * FROM orders WHERE id=?',(order_id,)).fetchone())
        order['lines']=[dict(r) for r in c.execute('SELECT * FROM order_lines WHERE order_id=?',(order_id,))]
    for line in order['lines']:line['modifiers']=json.loads(line['modifiers'] or '{}')
    return order

def chit_bytes(order):
    def add(out,text,indent=''):
        out.extend(textwrap.wrap(str(text),width=max(8,CHIT_COLUMNS-len(indent)),break_long_words=False,break_on_hyphens=False,subsequent_indent=indent) or [''])
    out=[]; add(out,f"COFFEE ORDER #{order['id']}");add(out,order['customer']);add(out,datetime.fromisoformat(order['created_at']).astimezone().strftime('%b %d  %I:%M %p'));add(out,'TO GO' if order['to_go'] else 'FOR HERE');out.append('-'*CHIT_COLUMNS)
    for line in order['lines']:
        add(out,f"{line['quantity']} x {line['name']}")
        for group,values in line['modifiers'].items():add(out,f"{group}: {', '.join(values)}",'  ')
    if order['notes']:out.append('-'*CHIT_COLUMNS);add(out,'NOTE: '+order['notes'])
    return b'\x1b@\x1ba\x00'+('\n'.join(out)+'\n\n\n\n\n\n').encode('utf-8','replace')+b'\x1dV\x00'

def send_chit(order):
    if PRINT_MODE=='mock':return
    if not EPSON_HOST:raise RuntimeError('EPSON_HOST is not configured')
    with socket.create_connection((EPSON_HOST,EPSON_PORT),timeout=8) as s:s.sendall(chit_bytes(order))

def label_font(size,bold=False):
    names=['DejaVuSans-Bold.ttf','DejaVuSans.ttf'] if bold else ['DejaVuSans.ttf']
    for name in names:
        try:return ImageFont.truetype(name,size)
        except OSError:pass
    return ImageFont.load_default()

def label_image(order,line):
    width,height=696,1100; image=Image.new('L',(width,height),'white');d=ImageDraw.Draw(image);y=35
    def block(text,size,bold=False,spacing=8):
        nonlocal y
        font=label_font(size,bold); avg=max(1,d.textlength('M',font=font)); chars=max(8,int((width-70)/avg))
        for row in textwrap.wrap(str(text),chars,break_long_words=False) or ['']:
            box=d.textbbox((0,0),row,font=font);x=(width-(box[2]-box[0]))//2;d.text((x,y),row,font=font,fill='black');y+=box[3]-box[1]+spacing
    block(order['customer'].upper(),72,True,14);d.line((40,y,width-40,y),fill='black',width=4);y+=22
    block(line['name'],64,True,16)
    for group,values in line['modifiers'].items():block(f"{group}: {', '.join(values)}",42,False,10)
    if order['notes']:y+=10;block(order['notes'],38,False,8)
    y=max(y,height-115);block(f"TO GO  •  ORDER #{order['id']}",34,True,4)
    return image

def send_labels(order):
    if PRINT_MODE=='mock':return
    if not BROTHER_HOST:raise RuntimeError('BROTHER_HOST is not configured')
    for line in order['lines']:
        for _ in range(line['quantity']):
            qlr=BrotherQLRaster(BROTHER_MODEL);brother_convert(qlr,[label_image(order,line)],BROTHER_LABEL_SIZE,cut=True,compress=True,rotate='0')
            with socket.create_connection((BROTHER_HOST,BROTHER_PORT),timeout=12) as s:s.sendall(bytes(qlr.data))

def process_print_job(job_id):
    with db() as c:
        job=c.execute('SELECT * FROM print_jobs WHERE id=?',(job_id,)).fetchone()
        if not job:return
        c.execute("UPDATE print_jobs SET status='printing',attempts=attempts+1,error='' WHERE id=?",(job_id,))
    try:
        order=order_payload(job['order_id']); send_chit(order) if job['printer']=='chit' else send_labels(order)
        with db() as c:c.execute("UPDATE print_jobs SET status='completed' WHERE id=?",(job_id,))
    except Exception as e:
        with db() as c:c.execute("UPDATE print_jobs SET status='failed',error=? WHERE id=?",(str(e)[:500],job_id))

def print_worker():
    while True:
        try:
            with db() as c: jobs=[r[0] for r in c.execute("SELECT id FROM print_jobs WHERE status='pending' ORDER BY id LIMIT 10")]
            for job_id in jobs:process_print_job(job_id)
        except Exception:pass
        time.sleep(2)

@app.get('/api/print-jobs')
@admin
def print_jobs():
    with db() as c:return jsonify([dict(r) for r in c.execute('SELECT p.*,o.customer,o.created_at FROM print_jobs p JOIN orders o ON o.id=p.order_id ORDER BY p.id DESC LIMIT 100')])

@app.post('/api/print-jobs/<int:job_id>/retry')
@admin
def retry_print_job(job_id):
    with db() as c:c.execute("UPDATE print_jobs SET status='pending',error='' WHERE id=?",(job_id,))
    return jsonify(ok=True)

@app.get('/api/health')
def health():return jsonify(status='ok')

init()
threading.Thread(target=print_worker,daemon=True,name='print-worker').start()
