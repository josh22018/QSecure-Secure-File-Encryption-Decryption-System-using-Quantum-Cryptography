import os
import sqlite3
import io
import json
import datetime
import math
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session,
    send_file, jsonify
)
import numpy as np

from crypto_utils import (
    aes_encrypt, aes_decrypt,
    wrap_key_hybrid, unwrap_key_hybrid,
    wrap_key_xor, unwrap_key_xor,
    hmac_params, verify_hmac_params
)
from hybrid_crypto import generate_keys, encrypt_hybrid, decrypt_hybrid
from pq_kyber import generate_keypair_kyber
from pq_ntru import encrypt_ntru, decrypt_ntru

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PARAM_HMAC_KEY'] = os.urandom(32)

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf', 'doc', 'docx'}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        c = db.cursor()
        c.execute('''
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            algorithm TEXT NOT NULL,
            encrypted_pw BLOB NOT NULL,
            rsa_priv BLOB NOT NULL,
            rsa_pub BLOB NOT NULL,
            ky_s_json TEXT NOT NULL,
            ky_pub_json TEXT NOT NULL,
            ntru_h_json TEXT NOT NULL
          )''')
        c.execute('''
          CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            filename TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
          )''')
        db.commit()

init_db()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_year():
    return {'current_year': datetime.datetime.now().year}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        algo = request.form['algorithm']

        db = get_db(); c = db.cursor()
        c.execute('SELECT 1 FROM users WHERE lower(username)=?', (username,))
        if c.fetchone():
            flash('Username already registered.', 'danger')
            db.close()
            return render_template('register.html')

        rsa_priv, rsa_pub = generate_keys()
        enc_pw = encrypt_hybrid(password.encode(), rsa_pub)

        (A, b), s = generate_keypair_kyber()
        ky_s_json = json.dumps(s)
        ky_pub_json = json.dumps({'A': A, 'b': b})
        h_list = np.random.randint(0, 4096, 701).tolist()
        ntru_h_json = json.dumps(h_list)

        c.execute('''
          INSERT INTO users(
            username, algorithm, encrypted_pw,
            rsa_priv, rsa_pub,
            ky_s_json, ky_pub_json,
            ntru_h_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            username, algo,
            sqlite3.Binary(enc_pw),
            sqlite3.Binary(rsa_priv), sqlite3.Binary(rsa_pub),
            ky_s_json, ky_pub_json,
            ntru_h_json
        ))
        db.commit(); db.close()

        flash('Registered! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        db = get_db(); c = db.cursor()
        c.execute('SELECT id, encrypted_pw, rsa_priv FROM users WHERE username=?', (username,))
        row = c.fetchone(); db.close()

        if not row:
            flash('Unknown username.', 'danger')
        else:
            user_id, enc_pw, rsa_priv = row
            try:
                dec = decrypt_hybrid(enc_pw, rsa_priv).decode()
                if dec == password:
                    session['user_id'] = user_id
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('dashboard'))
                flash('Incorrect password.', 'danger')
            except:
                flash('Decryption error.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('encrypt.html')

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt_file():
    f = request.files['file']
    algo = request.form['algorithm']
    filename = f.filename

    if not filename or not allowed_file(filename):
        flash('Invalid file.', 'danger')
        return redirect(url_for('dashboard'))

    # Collect user parameters
    params = {}
    if algo == 'kyber':
        params['n'] = int(request.form['n'])
        params['q'] = int(request.form['q'])
        params['k'] = int(request.form['k'])
    elif algo == 'ntru':
        params['N'] = int(request.form['N'])
        params['q'] = int(request.form['q'])
        params['p'] = int(request.form['p'])
    pj = json.dumps(params, sort_keys=True) if params else None
    ph = hmac_params(pj, app.config['PARAM_HMAC_KEY']) if pj else None

    # AES-GCM encrypt
    data = f.read()
    session['last_file_size'] = len(data)
    key, iv, tag, ct = aes_encrypt(data)

    db = get_db(); c = db.cursor()
    c.execute('SELECT rsa_pub FROM users WHERE id=?', (session['user_id'],))
    rsa_pub, = c.fetchone(); db.close()

    # Wrap key
    if algo == 'hybrid':
        wrapped = wrap_key_hybrid(key, rsa_pub)
    else:
        wrapped = wrap_key_xor(key, pj)

    pkg = {'wrapped': wrapped, 'iv': iv.hex(), 'tag': tag.hex(), 'ct': ct.hex()}
    if ph:
        pkg['params_hmac'] = ph

    # Log history
    ts = datetime.datetime.now().isoformat()
    db = get_db(); c = db.cursor()
    c.execute('''
      INSERT INTO history(user_id, action, algorithm, filename, timestamp)
      VALUES (?, ?, ?, ?, ?)
    ''', (session['user_id'], 'encrypt', algo, filename, ts))
    db.commit(); db.close()

    out = io.BytesIO(json.dumps(pkg).encode()); out.seek(0)
    return send_file(out, download_name=f"{filename}.enc", as_attachment=True)

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt_file():
    f = request.files['file']
    algo = request.form['algorithm']
    filename = f.filename

    if not filename.lower().endswith('.enc'):
        flash('Upload a .enc file.', 'danger')
        return redirect(url_for('dashboard'))

    pkg = json.loads(f.read().decode())
    ph = pkg.get('params_hmac')
    pj = None

    if ph:
        provided = {}
        if algo == 'kyber':
            provided['n'] = int(request.form['n'])
            provided['q'] = int(request.form['q'])
            provided['k'] = int(request.form['k'])
        elif algo == 'ntru':
            provided['N'] = int(request.form['N'])
            provided['q'] = int(request.form['q'])
            provided['p'] = int(request.form['p'])
        pj = json.dumps(provided, sort_keys=True)
        if not verify_hmac_params(pj, app.config['PARAM_HMAC_KEY'], ph):
            flash('Incorrect parameters.', 'danger')
            return redirect(url_for('dashboard'))

    iv = bytes.fromhex(pkg['iv'])
    tag = bytes.fromhex(pkg['tag'])
    ct = bytes.fromhex(pkg['ct'])
    wrapped = pkg['wrapped']

    db = get_db(); c = db.cursor()
    c.execute('SELECT rsa_priv FROM users WHERE id=?', (session['user_id'],))
    rsa_priv, = c.fetchone(); db.close()

    if algo == 'hybrid':
        key = unwrap_key_hybrid(wrapped, rsa_priv)
    else:
        key = unwrap_key_xor(wrapped, pj)

    try:
        data = aes_decrypt(key, iv, tag, ct)
    except:
        flash('Decryption failed.', 'danger')
        return redirect(url_for('dashboard'))

    session['last_file_size'] = len(data)
    ts = datetime.datetime.now().isoformat()
    db = get_db(); c = db.cursor()
    c.execute('''
      INSERT INTO history(user_id, action, algorithm, filename, timestamp)
      VALUES (?, ?, ?, ?, ?)
    ''', (session['user_id'], 'decrypt', algo, filename, ts))
    db.commit(); db.close()

    out = io.BytesIO(data); out.seek(0)
    return send_file(out, download_name=f"decrypted_{filename[:-4]}", as_attachment=True)

@app.route('/history')
@login_required
def history():
    db = get_db(); c = db.cursor()
    c.execute('''
      SELECT action, algorithm, filename, timestamp
      FROM history WHERE user_id=?
      ORDER BY id DESC
    ''', (session['user_id'],))
    records = c.fetchall(); db.close()
    return render_template('history.html', records=records)

@app.route('/simulation')
@login_required
def simulation():
    return render_template('simulation.html')

@app.route('/simulate_classical', methods=['POST'])
@login_required
def simulate_classical():
    payload = request.get_json(force=True)
    N = max(1, int(payload.get('N', 1)))
    target = min(N-1, max(0, int(payload.get('target', 0))))
    return jsonify({'count': target + 1})

@app.route('/simulate_grover', methods=['POST'])
@login_required
def simulate_grover():
    payload = request.get_json(force=True)
    N = max(1, int(payload.get('N', 1)))
    iterations = math.ceil((math.pi / 4) * math.sqrt(N))
    return jsonify({'iterations': iterations})

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
