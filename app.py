"""
DREAM – Digital Reservation Event and Automation Management
Flask Backend API  (app.py)  — PostgreSQL / Neon edition

Set the DATABASE_URL environment variable in Render to your Neon connection string:
  postgresql://user:password@ep-xxx.neon.tech/dbname?sslmode=require
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
import psycopg2.extras
import cloudinary
import cloudinary.uploader
import cloudinary.api

from flask import (
    Flask, request, jsonify, session,
    send_from_directory, send_file
)
from flask_cors import CORS

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dream-dev-secret-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE']   = os.environ.get('RENDER', False)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

CORS(app, supports_credentials=True,
     origins=os.environ.get('CORS_ORIGINS', 'http://localhost:5000').split(','))

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = BASE_DIR

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf'}

# ── Cloudinary setup ──────────────────────────────────────────
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key    = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET'),
    secure     = True
)

DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError('DATABASE_URL environment variable is not set.')

# Neon/Render sometimes give postgres:// — psycopg2 needs postgresql://
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# ── Database helpers ─────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = False
    return conn

def row_to_dict(row):
    """Convert a RealDictRow to a plain dict, parsing JSON columns."""
    d = dict(row)
    for col in ('extensions', 'misc_fees', 'consumables', 'materials', 'operators_list'):
        if col in d:
            val = d[col]
            if isinstance(val, str):
                try:
                    d[col] = json.loads(val)
                except (TypeError, json.JSONDecodeError):
                    d[col] = [] if col in ('extensions', 'misc_fees', 'operators_list') else {}
            elif val is None:
                d[col] = [] if col in ('extensions', 'misc_fees', 'operators_list') else {}
    d['operators'] = d.get('operators_list') or []
    for col in ('paid', 'completed', 'has_payment_proof', 'has_layout'):
        if col in d:
            d[col] = bool(d[col])
    return d

def normalize_unit(val) -> str:
    """Ensure booth/printer is always stored as a plain comma-separated string."""
    if val is None:
        return ''
    if isinstance(val, list):
        return ', '.join(str(v).strip() for v in val if v)
    return str(val).strip()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def now_ph() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Schema bootstrap (runs once on startup) ──────────────────
def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id       SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'operator'
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS packages (
            id         SERIAL PRIMARY KEY,
            name       TEXT NOT NULL,
            price      REAL NOT NULL DEFAULT 0,
            inclusions TEXT NOT NULL DEFAULT '[]'
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS selections (
            id        INTEGER PRIMARY KEY DEFAULT 1,
            operators TEXT NOT NULL DEFAULT '[]',
            booths    TEXT NOT NULL DEFAULT '[]',
            printers  TEXT NOT NULL DEFAULT '[]'
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id                SERIAL PRIMARY KEY,
            name              TEXT,
            date              TEXT,
            location          TEXT,
            client_name       TEXT,
            contact           TEXT,
            package           TEXT,
            package_price     REAL    DEFAULT 0,
            down_payment      REAL    DEFAULT 0,
            balance           REAL    DEFAULT 0,
            paid              BOOLEAN DEFAULT FALSE,
            completed         BOOLEAN DEFAULT FALSE,
            completed_at      TEXT,
            booth             TEXT,
            printer           TEXT,
            time_start        TEXT,
            time_end          TEXT,
            operator          TEXT,
            operators_list    TEXT    DEFAULT '[]',
            extensions        TEXT    DEFAULT '[]',
            misc_fees         TEXT    DEFAULT '[]',
            misc_total        REAL    DEFAULT 0,
            consumables       TEXT    DEFAULT '{}',
            materials         TEXT    DEFAULT '{}',
            has_payment_proof BOOLEAN DEFAULT FALSE,
            has_layout        BOOLEAN DEFAULT FALSE,
            created_at        TEXT
        )
    ''')
    # Seed a default admin if no users exist
    cur.execute('SELECT COUNT(*) AS cnt FROM users')
    count = cur.fetchone()['cnt']
    if count == 0:
        cur.execute(
            'INSERT INTO users (username, password, role) VALUES (%s, %s, %s)',
            ('admin', hash_password('admin123'), 'admin')
        )
        print('[DREAM] Default admin created — username: admin  password: admin123')
    conn.commit()
    cur.close()
    conn.close()

# ── Auth decorators ───────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        if session.get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username=%s AND password=%s',
                (username, hash_password(password)))
    user = cur.fetchone()
    cur.close(); conn.close()
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    session.permanent = True
    session['user'] = user['username']
    session['role'] = user['role']
    return jsonify({'username': user['username'], 'role': user['role']})


@app.route('/api/auth/me')
def auth_me():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({'username': session['user'], 'role': session['role']})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    data       = request.get_json(force=True)
    current_pw = data.get('current_password', '')
    new_pw     = data.get('new_password', '')
    if not current_pw or not new_pw:
        return jsonify({'error': 'Both current and new password are required'}), 400
    if len(new_pw) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username=%s AND password=%s',
                (session['user'], hash_password(current_pw)))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401
    cur.execute('UPDATE users SET password=%s WHERE username=%s',
                (hash_password(new_pw), session['user']))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  ACCOUNTS
# ══════════════════════════════════════════════════════════════

@app.route('/api/accounts', methods=['GET'])
@login_required
def get_accounts():
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT id, username, role FROM users ORDER BY role, username')
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/accounts', methods=['POST'])
@admin_required
def create_account():
    data     = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    role     = data.get('role', 'operator')
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if role not in ('admin', 'operator'):
        return jsonify({'error': 'Role must be admin or operator'}), 400
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute('INSERT INTO users (username, password, role) VALUES (%s,%s,%s)',
                    (username, hash_password(password), role))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); cur.close(); conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    cur.close(); conn.close()
    return jsonify({'username': username, 'role': role}), 201


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@admin_required
def delete_account(account_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT username FROM users WHERE id=%s', (account_id,))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return jsonify({'error': 'Account not found'}), 404
    if user['username'] == session.get('user'):
        cur.close(); conn.close()
        return jsonify({'error': 'Cannot delete your own account'}), 400
    cur.execute('DELETE FROM users WHERE id=%s', (account_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True})


@app.route('/api/accounts/<int:account_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_password(account_id):
    data   = request.get_json(force=True)
    new_pw = (data.get('new_password') or '').strip()
    if not new_pw or len(new_pw) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT id FROM users WHERE id=%s', (account_id,))
    if not cur.fetchone():
        cur.close(); conn.close()
        return jsonify({'error': 'Account not found'}), 404
    cur.execute('UPDATE users SET password=%s WHERE id=%s',
                (hash_password(new_pw), account_id))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  PACKAGES
# ══════════════════════════════════════════════════════════════

@app.route('/api/packages', methods=['GET'])
@login_required
def get_packages():
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM packages ORDER BY id')
    rows = cur.fetchall(); cur.close(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if 'inclusions' in d and isinstance(d['inclusions'], str):
            try: d['inclusions'] = json.loads(d['inclusions'])
            except: d['inclusions'] = []
        result.append(d)
    return jsonify(result)


@app.route('/api/packages', methods=['POST'])
@admin_required
def create_package():
    data  = request.get_json(force=True)
    name  = (data.get('name') or '').strip()
    price = float(data.get('price', 0))
    if not name:
        return jsonify({'error': 'Package name required'}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute('INSERT INTO packages (name, price, inclusions) VALUES (%s,%s,%s) RETURNING id',
                (name, price, json.dumps(data.get('inclusions', []))))
    pkg_id = cur.fetchone()['id']
    conn.commit(); cur.close(); conn.close()
    return jsonify({'id': pkg_id, 'name': name, 'price': price}), 201


@app.route('/api/packages/<int:pkg_id>', methods=['PUT'])
@admin_required
def update_package(pkg_id):
    data  = request.get_json(force=True)
    name  = (data.get('name') or '').strip()
    price = float(data.get('price', 0))
    inclusions = data.get('inclusions', [])
    conn = get_db(); cur = conn.cursor()
    cur.execute('UPDATE packages SET name=%s, price=%s, inclusions=%s WHERE id=%s',
                (name, price, json.dumps(inclusions), pkg_id))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'id': pkg_id, 'name': name, 'price': price, 'inclusions': inclusions})


@app.route('/api/packages/<int:pkg_id>', methods=['DELETE'])
@admin_required
def delete_package(pkg_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute('DELETE FROM packages WHERE id=%s', (pkg_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  SELECTIONS
# ══════════════════════════════════════════════════════════════

@app.route('/api/selections', methods=['GET'])
@login_required
def get_selections():
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM selections WHERE id=1')
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        return jsonify({'operators': [], 'boothUnits': [], 'printerUnits': []})
    return jsonify({
        'operators':    json.loads(row['operators'] or '[]'),
        'boothUnits':   json.loads(row['booths']    or '[]'),
        'printerUnits': json.loads(row['printers']  or '[]'),
    })


@app.route('/api/selections', methods=['POST', 'PUT'])
@admin_required
def save_selections():
    data     = request.get_json(force=True)
    booths   = data.get('boothUnits',   data.get('booths',   []))
    printers = data.get('printerUnits', data.get('printers', []))
    conn = get_db(); cur = conn.cursor()
    cur.execute('''
        INSERT INTO selections (id, operators, booths, printers)
        VALUES (1, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            operators = EXCLUDED.operators,
            booths    = EXCLUDED.booths,
            printers  = EXCLUDED.printers
    ''', (json.dumps(data.get('operators', [])),
          json.dumps(booths),
          json.dumps(printers)))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  EVENTS
# ══════════════════════════════════════════════════════════════

@app.route('/api/events', methods=['GET'])
@login_required
def get_events():
    year  = request.args.get('year',  type=int)
    month = request.args.get('month', type=int)
    conn  = get_db(); cur = conn.cursor()
    if year and month:
        prefix = f'{year}-{month:02d}-'
        cur.execute("SELECT * FROM events WHERE date LIKE %s ORDER BY date",
                    (prefix + '%',))
    else:
        cur.execute('SELECT * FROM events ORDER BY date')
    rows = cur.fetchall(); cur.close(); conn.close()
    return jsonify([row_to_dict(r) for r in rows])


@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    data = request.get_json(force=True)
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO events (
                name, date, location, client_name, contact,
                package, package_price, down_payment, balance,
                paid, completed, booth, printer,
                time_start, time_end, operator,
                operators_list, extensions, misc_fees, misc_total,
                consumables, materials,
                has_payment_proof, has_layout, created_at
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
        ''', (
            data.get('name'),
            data.get('date'),
            data.get('location'),
            data.get('client_name'),
            data.get('contact'),
            data.get('package'),
            float(data.get('package_price') or 0),
            float(data.get('down_payment')  or 0),
            float(data.get('balance')       or 0),
            bool(data.get('paid',      False)),
            bool(data.get('completed', False)),
            normalize_unit(data.get('booth')),
            normalize_unit(data.get('printer')),
            data.get('time_start'),
            data.get('time_end'),
            data.get('operator'),
            json.dumps(data.get('operators',   [])),
            json.dumps(data.get('extensions',  [])),
            json.dumps(data.get('misc_fees',   [])),
            float(data.get('misc_total') or 0),
            json.dumps(data.get('consumables', {'pre': {'photo': 0, 'mag': 0}, 'post': {'photo': 0, 'mag': 0}})),
            json.dumps(data.get('materials',   {})),
            bool(data.get('has_payment_proof', False)),
            bool(data.get('has_layout',        False)),
            now_ph(),
        ))
        event_id = cur.fetchone()['id']
        conn.commit()
        cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
        row = cur.fetchone(); cur.close(); conn.close()
        return jsonify(row_to_dict(row)), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        conn.rollback(); cur.close(); conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<int:event_id>', methods=['GET'])
@login_required
def get_event(event_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        return jsonify({'error': 'Event not found'}), 404
    return jsonify(row_to_dict(row))


@app.route('/api/events/<int:event_id>', methods=['PUT'])
@login_required
def update_event(event_id):
    data = request.get_json(force=True)
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    existing = cur.fetchone()
    if not existing:
        cur.close(); conn.close()
        return jsonify({'error': 'Event not found'}), 404
    try:
        cur.execute('''
            UPDATE events SET
                name=%s, date=%s, location=%s, client_name=%s, contact=%s,
                package=%s, package_price=%s, down_payment=%s, balance=%s,
                paid=%s, completed=%s, booth=%s, printer=%s,
                time_start=%s, time_end=%s, operator=%s,
                operators_list=%s, extensions=%s, misc_fees=%s, misc_total=%s,
                consumables=%s, materials=%s,
                has_payment_proof=%s, has_layout=%s
            WHERE id=%s
        ''', (
            data.get('name',         existing['name']),
            data.get('date',         existing['date']),
            data.get('location',     existing['location']),
            data.get('client_name',  existing['client_name']),
            data.get('contact',      existing['contact']),
            data.get('package',      existing['package']),
            float(data.get('package_price', existing['package_price']) or 0),
            float(data.get('down_payment',  existing['down_payment'])  or 0),
            float(data.get('balance',       existing['balance'])       or 0),
            bool(data.get('paid',      existing['paid'])),
            bool(data.get('completed', existing['completed'])),
            normalize_unit(data.get('booth',   existing['booth'])),
            normalize_unit(data.get('printer', existing['printer'])),
            data.get('time_start', existing['time_start']),
            data.get('time_end',   existing['time_end']),
            data.get('operator',   existing['operator']),
            json.dumps(data.get('operators',  json.loads(existing['operators_list'] or '[]'))),
            json.dumps(data.get('extensions', json.loads(existing['extensions']     or '[]'))),
            json.dumps(data.get('misc_fees',  json.loads(existing['misc_fees']      or '[]'))),
            float(data.get('misc_total', existing['misc_total']) or 0),
            json.dumps(data.get('consumables', json.loads(existing['consumables'] or '{}'))),
            json.dumps(data.get('materials',   json.loads(existing['materials']   or '{}'))),
            bool(data.get('has_payment_proof', existing['has_payment_proof'])),
            bool(data.get('has_layout',        existing['has_layout'])),
            event_id,
        ))
        conn.commit()
        cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
        row = cur.fetchone(); cur.close(); conn.close()
        return jsonify(row_to_dict(row))
    except Exception as e:
        import traceback
        traceback.print_exc()
        conn.rollback(); cur.close(); conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute('DELETE FROM events WHERE id=%s', (event_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True})


# ── Mark event completed ──────────────────────────────────────
@app.route('/api/events/<int:event_id>/complete', methods=['POST'])
@login_required
def complete_event(event_id):
    data       = request.get_json(force=True) or {}
    misc_fees  = data.get('misc_fees', [])
    misc_total = sum(float(m.get('amount', 0)) for m in misc_fees)
    conn = get_db(); cur = conn.cursor()
    cur.execute('''
        UPDATE events SET
            completed=TRUE, completed_at=%s,
            consumables=%s, misc_fees=%s, misc_total=%s
        WHERE id=%s
    ''', (now_ph(), json.dumps(data.get('consumables', {})),
          json.dumps(misc_fees), misc_total, event_id))
    conn.commit()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    return jsonify(row_to_dict(row))


# ── Add extension ─────────────────────────────────────────────
@app.route('/api/events/<int:event_id>/extend', methods=['POST'])
@login_required
def extend_event(event_id):
    data = request.get_json(force=True)
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({'error': 'Event not found'}), 404
    extensions = json.loads(row['extensions'] or '[]')
    extensions.append({
        'duration': data.get('duration'),
        'amount':   float(data.get('amount', 0)),
        'notes':    data.get('notes', ''),
        'added_at': now_ph(),
    })
    cur.execute('UPDATE events SET extensions=%s WHERE id=%s',
                (json.dumps(extensions), event_id))
    conn.commit()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    return jsonify(row_to_dict(row))


# ── Delete a single extension ─────────────────────────────────
@app.route('/api/events/<int:event_id>/extensions/<int:ext_idx>', methods=['DELETE'])
@login_required
def delete_extension(event_id, ext_idx):
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({'error': 'Event not found'}), 404
    extensions = json.loads(row['extensions'] or '[]')
    if ext_idx < 0 or ext_idx >= len(extensions):
        cur.close(); conn.close()
        return jsonify({'error': 'Extension index out of range'}), 400
    extensions.pop(ext_idx)
    cur.execute('UPDATE events SET extensions=%s WHERE id=%s',
                (json.dumps(extensions), event_id))
    conn.commit()
    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    return jsonify(row_to_dict(row))


# ── Delete all events in a month ─────────────────────────────
@app.route('/api/events/delete-month', methods=['DELETE'])
@admin_required
def delete_month_events():
    year  = request.args.get('year',  type=int)
    month = request.args.get('month', type=int)
    if not year or not month:
        return jsonify({'error': 'year and month required'}), 400
    prefix = f'{year}-{month:02d}-'
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM events WHERE date LIKE %s", (prefix + '%',))
    deleted = cur.rowcount
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True, 'deleted': deleted})


# ── File uploads ──────────────────────────────────────────────
@app.route('/api/events/<int:event_id>/upload', methods=['POST'])
@login_required
def upload_file(event_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file        = request.files['file']
    upload_type = request.form.get('type', 'payment')
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    # Upload to Cloudinary — public_id keeps one file per event+type (auto-replaces old one)
    public_id = f'dream/event_{event_id}_{upload_type}'
    try:
        result = cloudinary.uploader.upload(
            file,
            public_id        = public_id,
            overwrite        = True,
            resource_type    = 'auto',   # handles both images and PDFs
            invalidate       = True,
        )
    except Exception as e:
        return jsonify({'error': f'Cloudinary upload failed: {str(e)}'}), 500

    file_url = result['secure_url']

    conn = get_db(); cur = conn.cursor()
    if upload_type == 'payment':
        cur.execute(
            'UPDATE events SET has_payment_proof=TRUE WHERE id=%s', (event_id,)
        )
    else:
        cur.execute(
            'UPDATE events SET has_layout=TRUE WHERE id=%s', (event_id,)
        )
    conn.commit(); cur.close(); conn.close()
    return jsonify({'ok': True, 'url': file_url})


@app.route('/api/events/<int:event_id>/upload-url/<upload_type>')
@login_required
def get_upload_url(event_id, upload_type):
    if upload_type not in ('payment', 'layout'):
        return jsonify({'error': 'Invalid upload type'}), 400

    public_id = f'dream/event_{event_id}_{upload_type}'
    try:
        # Check if the resource exists on Cloudinary
        result = cloudinary.api.resource(public_id, resource_type='image')
        return jsonify({'url': result['secure_url']})
    except Exception:
        # Try as raw (PDF)
        try:
            result = cloudinary.api.resource(public_id, resource_type='raw')
            return jsonify({'url': result['secure_url']})
        except Exception:
            return jsonify({'error': 'File not found'}), 404


# ── Equipment availability ────────────────────────────────────
@app.route('/api/events/availability', methods=['GET'])
@login_required
def get_availability():
    """
    Returns which booths and printers are already booked on a given date
    and time range (overlapping events).

    Query params:
      date        – YYYY-MM-DD
      time_start  – HH:MM
      time_end    – HH:MM
      exclude_id  – (optional) event id to ignore (used when editing)
    """
    date       = request.args.get('date', '')
    time_start = request.args.get('time_start', '')
    time_end   = request.args.get('time_end', '')
    exclude_id = request.args.get('exclude_id', type=int)

    if not date or not time_start or not time_end:
        return jsonify({'booths': [], 'printers': []})

    conn = get_db(); cur = conn.cursor()
    try:
        # Fetch all non-completed events on the same date
        cur.execute(
            "SELECT id, booth, printer, time_start, time_end FROM events "
            "WHERE date = %s AND completed = FALSE",
            (date,)
        )
        rows = cur.fetchall()
    finally:
        cur.close(); conn.close()

    busy_booths   = set()
    busy_printers = set()

    def times_overlap(s1, e1, s2, e2):
        """Return True if [s1,e1) overlaps [s2,e2). Strings in HH:MM format."""
        try:
            # Treat times as simple string-comparable values (HH:MM sorts correctly)
            return s1 < e2 and s2 < e1
        except Exception:
            return False

    for row in rows:
        if exclude_id and row['id'] == exclude_id:
            continue
        rs = row['time_start'] or ''
        re = row['time_end']   or ''
        if not rs or not re:
            continue
        if times_overlap(time_start, time_end, rs, re):
            # booth / printer columns may hold comma-separated values (multi-select)
            if row['booth']:
                for b in row['booth'].split(','):
                    b = b.strip()
                    if b:
                        busy_booths.add(b)
            if row['printer']:
                for p in row['printer'].split(','):
                    p = p.strip()
                    if p:
                        busy_printers.add(p)

    return jsonify({'booths': list(busy_booths), 'printers': list(busy_printers)})


# ══════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'time': now_ph()})


# ══════════════════════════════════════════════════════════════
#  SERVE FRONTEND
# ══════════════════════════════════════════════════════════════

@app.route('/')
def serve_frontend():
    return send_file(os.path.join(FRONTEND_DIR, 'index.html'))


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
