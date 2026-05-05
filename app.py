"""
DREAM – Digital Reservation Event and Automation Management
Flask Backend API  (app.py)

Routes implemented:
  POST   /auth/login
  GET    /auth/me
  POST   /auth/logout

  GET    /accounts
  POST   /accounts
  DELETE /accounts/<username>

  GET    /packages
  POST   /packages
  PUT    /packages/<int:pkg_id>
  DELETE /packages/<int:pkg_id>

  GET    /selections
  POST   /selections

  GET    /events?year=&month=
  POST   /events
  GET    /events/<int:event_id>
  PUT    /events/<int:event_id>
  DELETE /events/<int:event_id>

  POST   /events/<int:event_id>/complete
  POST   /events/<int:event_id>/extend
  POST   /events/<int:event_id>/upload
  GET    /uploads/<filename>
"""

import os
import json
import hashlib
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, request, jsonify, session,
    send_from_directory, abort, send_file
)
from flask_cors import CORS

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dream-dev-secret-change-in-production')
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

CORS(app, supports_credentials=True, origins=['http://localhost:5000', 'http://127.0.0.1:5000'])

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, 'dream.db')
UPLOAD_DIR  = os.path.join(BASE_DIR, 'uploads')
FRONTEND_DIR = BASE_DIR  # index.html lives in the same folder
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf'}

# ── Database helpers ─────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict, parsing any JSON TEXT columns."""
    d = dict(row)
    for col in ('extensions', 'misc_fees', 'consumables', 'materials', 'operators_list'):
        if col in d and isinstance(d[col], str):
            try:
                d[col] = json.loads(d[col])
            except (TypeError, json.JSONDecodeError):
                d[col] = [] if col in ('extensions', 'misc_fees', 'operators_list') else {}
    # Alias operators_list as operators for frontend compatibility
    d['operators'] = d.get('operators_list', [])
    # Boolean fields stored as INTEGER
    for col in ('paid', 'completed'):
        if col in d:
            d[col] = bool(d[col])
    return d

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def now_ph() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Auth decorator ────────────────────────────────────────────
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
    data = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        (username, hash_password(password))
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    
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
    data = request.get_json(force=True)
    current_pw = data.get('current_password', '')
    new_pw     = data.get('new_password', '')

    if not current_pw or not new_pw:
        return jsonify({'error': 'Both current and new password are required'}), 400
    if len(new_pw) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        (session['user'], hash_password(current_pw))
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401

    conn.execute(
        'UPDATE users SET password = ? WHERE username = ?',
        (hash_password(new_pw), session['user'])
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  ACCOUNTS
# ══════════════════════════════════════════════════════════════

@app.route('/api/accounts', methods=['GET'])
@login_required
def get_accounts():
    conn = get_db()
    rows = conn.execute('SELECT id, username, role FROM users ORDER BY role, username').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/accounts', methods=['POST'])
@admin_required
def create_account():
    data = request.get_json(force=True)
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    role     = data.get('role', 'operator')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if role not in ('admin', 'operator'):
        return jsonify({'error': 'Role must be admin or operator'}), 400

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, hash_password(password), role)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    conn.close()
    return jsonify({'username': username, 'role': role}), 201


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@admin_required
def delete_account(account_id):
    conn = get_db()
    user = conn.execute('SELECT username FROM users WHERE id=?', (account_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Account not found'}), 404
    if user['username'] == session.get('user'):
        conn.close()
        return jsonify({'error': 'Cannot delete your own account'}), 400
    conn.execute('DELETE FROM users WHERE id=?', (account_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/accounts/<int:account_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_password(account_id):
    data = request.get_json(force=True)
    new_pw = (data.get('new_password') or '').strip()
    if not new_pw or len(new_pw) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    conn = get_db()
    user = conn.execute('SELECT id FROM users WHERE id=?', (account_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Account not found'}), 404
    conn.execute('UPDATE users SET password=? WHERE id=?', (hash_password(new_pw), account_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  PACKAGES
# ══════════════════════════════════════════════════════════════

@app.route('/api/packages', methods=['GET'])
@login_required
def get_packages():
    conn = get_db()
    rows = conn.execute('SELECT * FROM packages ORDER BY id').fetchall()
    conn.close()
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
    data = request.get_json(force=True)
    name  = (data.get('name') or '').strip()
    price = float(data.get('price', 0))
    if not name:
        return jsonify({'error': 'Package name required'}), 400

    conn = get_db()
    inclusions = data.get('inclusions', [])
    cur = conn.execute(
        'INSERT INTO packages (name, price, inclusions) VALUES (?, ?, ?)', (name, price, json.dumps(inclusions))
    )
    conn.commit()
    pkg_id = cur.lastrowid
    conn.close()
    return jsonify({'id': pkg_id, 'name': name, 'price': price}), 201


@app.route('/api/packages/<int:pkg_id>', methods=['PUT'])
@admin_required
def update_package(pkg_id):
    data  = request.get_json(force=True)
    name  = (data.get('name') or '').strip()
    price = float(data.get('price', 0))
    conn  = get_db()
    inclusions = data.get('inclusions', [])
    conn.execute('UPDATE packages SET name=?, price=?, inclusions=? WHERE id=?', (name, price, json.dumps(inclusions), pkg_id))
    conn.commit()
    conn.close()
    return jsonify({'id': pkg_id, 'name': name, 'price': price, 'inclusions': inclusions})


@app.route('/api/packages/<int:pkg_id>', methods=['DELETE'])
@admin_required
def delete_package(pkg_id):
    conn = get_db()
    conn.execute('DELETE FROM packages WHERE id=?', (pkg_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  SELECTIONS  (operators list, booths, printers)
# ══════════════════════════════════════════════════════════════

@app.route('/api/selections', methods=['GET'])
@login_required
def get_selections():
    conn = get_db()
    row  = conn.execute('SELECT * FROM selections WHERE id=1').fetchone()
    conn.close()
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
    data = request.get_json(force=True)
    booths   = data.get('boothUnits',   data.get('booths',   []))
    printers = data.get('printerUnits', data.get('printers', []))
    conn = get_db()
    conn.execute('''
        INSERT INTO selections (id, operators, booths, printers)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            operators=excluded.operators,
            booths=excluded.booths,
            printers=excluded.printers
    ''', (
        json.dumps(data.get('operators', [])),
        json.dumps(booths),
        json.dumps(printers),
    ))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  EVENTS
# ══════════════════════════════════════════════════════════════

@app.route('/api/events', methods=['GET'])
@login_required
def get_events():
    year  = request.args.get('year',  type=int)
    month = request.args.get('month', type=int)

    conn = get_db()
    if year and month:
        prefix = f'{year}-{month:02d}-'
        rows = conn.execute(
            "SELECT * FROM events WHERE date LIKE ? ORDER BY date",
            (prefix + '%',)
        ).fetchall()
    else:
        rows = conn.execute('SELECT * FROM events ORDER BY date').fetchall()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])


@app.route('/api/events', methods=['POST'])
@login_required
def create_event():
    data = request.get_json(force=True)
    conn = get_db()
    cur  = conn.execute('''
        INSERT INTO events (
            name, date, location, client_name, contact,
            package, package_price, down_payment, balance,
            paid, completed, booth, printer,
            time_start, time_end, operator,
            operators_list, extensions, misc_fees, misc_total,
            consumables, materials,
            has_payment_proof, has_layout, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
        int(bool(data.get('paid',       False))),
        int(bool(data.get('completed',  False))),
        data.get('booth'),
        data.get('printer'),
        data.get('time_start'),
        data.get('time_end'),
        data.get('operator'),
        json.dumps(data.get('operators',     [])),
        json.dumps(data.get('extensions',    [])),
        json.dumps(data.get('misc_fees',     [])),
        float(data.get('misc_total') or 0),
        json.dumps(data.get('consumables',   {'pre': {'photo': 0, 'mag': 0}, 'post': {'photo': 0, 'mag': 0}})),
        json.dumps(data.get('materials',     {})),
        int(bool(data.get('has_payment_proof', False))),
        int(bool(data.get('has_layout',        False))),
        now_ph(),
    ))
    conn.commit()
    event_id = cur.lastrowid
    row = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    conn.close()
    return jsonify(row_to_dict(row)), 201


@app.route('/api/events/<int:event_id>', methods=['GET'])
@login_required
def get_event(event_id):
    conn = get_db()
    row  = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Event not found'}), 404
    return jsonify(row_to_dict(row))


@app.route('/api/events/<int:event_id>', methods=['PUT'])
@login_required
def update_event(event_id):
    data = request.get_json(force=True)
    conn = get_db()
    existing = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Event not found'}), 404

    conn.execute('''
        UPDATE events SET
            name=?, date=?, location=?, client_name=?, contact=?,
            package=?, package_price=?, down_payment=?, balance=?,
            paid=?, completed=?, booth=?, printer=?,
            time_start=?, time_end=?, operator=?,
            operators_list=?, extensions=?, misc_fees=?, misc_total=?,
            consumables=?, materials=?,
            has_payment_proof=?, has_layout=?
        WHERE id=?
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
        int(bool(data.get('paid',       existing['paid']))),
        int(bool(data.get('completed',  existing['completed']))),
        data.get('booth',    existing['booth']),
        data.get('printer',  existing['printer']),
        data.get('time_start', existing['time_start']),
        data.get('time_end',   existing['time_end']),
        data.get('operator',   existing['operator']),
        json.dumps(data.get('operators',  json.loads(existing['operators_list'] or '[]'))),
        json.dumps(data.get('extensions', json.loads(existing['extensions']     or '[]'))),
        json.dumps(data.get('misc_fees',  json.loads(existing['misc_fees']      or '[]'))),
        float(data.get('misc_total', existing['misc_total']) or 0),
        json.dumps(data.get('consumables', json.loads(existing['consumables'] or '{}'))),
        json.dumps(data.get('materials',   json.loads(existing['materials']   or '{}'))),
        int(bool(data.get('has_payment_proof', existing['has_payment_proof']))),
        int(bool(data.get('has_layout',        existing['has_layout']))),
        event_id,
    ))
    conn.commit()
    row = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    conn.close()
    return jsonify(row_to_dict(row))


@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    conn = get_db()
    conn.execute('DELETE FROM events WHERE id=?', (event_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ── Mark event completed ──────────────────────────────────────
@app.route('/api/events/<int:event_id>/complete', methods=['POST'])
@login_required
def complete_event(event_id):
    data = request.get_json(force=True) or {}
    misc_fees = data.get('misc_fees', [])
    misc_total = sum(float(m.get('amount', 0)) for m in misc_fees)
    conn = get_db()
    conn.execute('''
        UPDATE events SET
            completed=1, completed_at=?,
            consumables=?,
            misc_fees=?,
            misc_total=?
        WHERE id=?
    ''', (
        now_ph(),
        json.dumps(data.get('consumables', {})),
        json.dumps(misc_fees),
        misc_total,
        event_id,
    ))
    conn.commit()
    row = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    conn.close()
    return jsonify(row_to_dict(row))


# ── Add extension ─────────────────────────────────────────────
@app.route('/api/events/<int:event_id>/extend', methods=['POST'])
@login_required
def extend_event(event_id):
    data = request.get_json(force=True)
    conn = get_db()
    row  = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Event not found'}), 404

    extensions = json.loads(row['extensions'] or '[]')
    new_ext = {
        'duration': data.get('duration'),
        'amount':   float(data.get('amount', 0)),
        'notes':    data.get('notes', ''),
        'added_at': now_ph(),
    }
    extensions.append(new_ext)

    conn.execute(
        'UPDATE events SET extensions=? WHERE id=?',
        (json.dumps(extensions), event_id)
    )
    conn.commit()
    row = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    conn.close()
    return jsonify(row_to_dict(row))


# ── File uploads ──────────────────────────────────────────────
@app.route('/api/events/<int:event_id>/upload', methods=['POST'])
@login_required
def upload_file(event_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file        = request.files['file']
    upload_type = request.form.get('type', 'payment')   # 'payment' or 'layout'

    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    ext      = file.filename.rsplit('.', 1)[1].lower()
    filename = f'event_{event_id}_{upload_type}.{ext}'
    file.save(os.path.join(UPLOAD_DIR, filename))

    conn = get_db()
    if upload_type == 'payment':
        conn.execute('UPDATE events SET has_payment_proof=1 WHERE id=?', (event_id,))
    else:
        conn.execute('UPDATE events SET has_layout=1 WHERE id=?', (event_id,))
    conn.commit()
    conn.close()

    return jsonify({'ok': True, 'filename': filename, 'url': f'/api/uploads/{filename}'})


@app.route('/api/uploads/<path:filename>')
def serve_upload(filename):
    # Session cookies ARE sent by <img> tags on same origin.
    # We keep the check but return 404 (not 401) so the browser
    # doesn't treat it as an auth error and block the request.
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    safe_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(safe_path):
        return jsonify({'error': 'File not found'}), 404
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/api/events/<int:event_id>/upload-url/<upload_type>')
@login_required
def get_upload_url(event_id, upload_type):
    """Find and return the actual URL of an uploaded file by scanning the upload directory."""
    if upload_type not in ('payment', 'layout'):
        return jsonify({'error': 'Invalid upload type'}), 400
    for ext in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf']:
        filename = f'event_{event_id}_{upload_type}.{ext}'
        full_path = os.path.join(UPLOAD_DIR, filename)
        app.logger.debug(f'[upload-url] checking: {full_path} -> exists={os.path.exists(full_path)}')
        if os.path.exists(full_path):
            return jsonify({'url': f'/api/uploads/{filename}', 'filename': filename})
    app.logger.debug(f'[upload-url] UPLOAD_DIR={UPLOAD_DIR}, files={os.listdir(UPLOAD_DIR) if os.path.exists(UPLOAD_DIR) else "DIR NOT FOUND"}')
    return jsonify({'error': 'File not found', 'upload_dir': UPLOAD_DIR, 'exists': os.path.exists(UPLOAD_DIR)}), 404




# ── Delete all events in a month ─────────────────────────────
@app.route('/api/events/delete-month', methods=['DELETE'])
@admin_required
def delete_month_events():
    year  = request.args.get('year',  type=int)
    month = request.args.get('month', type=int)
    if not year or not month:
        return jsonify({'error': 'year and month required'}), 400
    prefix = f'{year}-{month:02d}-'
    conn = get_db()
    conn.execute("DELETE FROM events WHERE date LIKE ?", (prefix + '%',))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ── Delete a single extension from an event ──────────────────
@app.route('/api/events/<int:event_id>/extensions/<int:ext_idx>', methods=['DELETE'])
@admin_required
def delete_extension(event_id, ext_idx):
    conn = get_db()
    row  = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Event not found'}), 404
    extensions = json.loads(row['extensions'] or '[]')
    if ext_idx < 0 or ext_idx >= len(extensions):
        conn.close()
        return jsonify({'error': 'Extension index out of range'}), 400
    extensions.pop(ext_idx)
    conn.execute('UPDATE events SET extensions=? WHERE id=?', (json.dumps(extensions), event_id))
    conn.commit()
    row = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    conn.close()
    return jsonify(row_to_dict(row))

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

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
