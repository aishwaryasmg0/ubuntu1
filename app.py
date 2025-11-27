from flask import Flask, render_template, request, jsonify, redirect, session, send_from_directory
from flask_session import Session
import subprocess
import threading
import time
import os
import json
from datetime import timedelta

app = Flask(__name__)

# ==================== SESSION CONFIGURATION ====================
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_PERMANENT'] = False
Session(app)

# ==================== CREDENTIALS (Change in Production!) ====================
VALID_USERS = {
    'admin': 'admin123',
    'pentest': 'pentest@2024',
    'user': 'user123'
}

# ==================== GLOBAL VARIABLES ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_SHELL_SCRIPT = os.path.join(SCRIPT_DIR, 'app.sh')

log_queue = []
vuln_queue = []
scanning = False

# ==================== AUTHENTICATION ROUTES ====================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    # Validate credentials
    if username in VALID_USERS and VALID_USERS[username] == password:
        session['user_id'] = username
        session['logged_in'] = True
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': '/dashboard'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        }), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'redirect': '/'})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if session.get('logged_in'):
        return jsonify({
            'authenticated': True,
            'user': session.get('user_id')
        })
    else:
        return jsonify({'authenticated': False}), 401

# ==================== MIDDLEWARE ====================
def is_authenticated():
    return session.get('logged_in', False)

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ==================== PAGE ROUTES ====================
@app.route('/')
def login_page():
    if is_authenticated():
        return redirect('/dashboard')
   
    try:
        with open(os.path.join(SCRIPT_DIR, 'login.html'), 'r') as f:
            return f.read()
    except:
        return "Error: login.html not found", 404

@app.route('/dashboard')
def dashboard():
    if not is_authenticated():
        return redirect('/')
   
    try:
        with open(os.path.join(SCRIPT_DIR, 'index.html'), 'r') as f:
            return f.read()
    except:
        return "Error: index.html not found", 404

# ==================== PROTECTED API ROUTES ====================
@app.route('/run-recon', methods=['POST'])
@require_auth
def run_recon():
    global log_queue, vuln_queue, scanning

    data = request.json
    domain = data.get('domain', 'example.com')

    log_queue = []
    vuln_queue = []
    scanning = True

    def execute():
        global log_queue, vuln_queue, scanning
        try:
            cmd = f"bash {APP_SHELL_SCRIPT} {domain}"
            log_queue.append(f"[*] Starting scan for {domain}...")
            log_queue.append(f"[*] Please wait for all steps...")
           
            process = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                line = line.rstrip('\n\r')
                if line:
                    log_queue.append(line)
                    if ("###VULN###" in line) and ("###END###" in line):
                        vuln_queue.append(line)
                time.sleep(0.01)

            process.wait()
        except Exception as e:
            log_queue.append(f"❌ ERROR: {str(e)}")
        finally:
            scanning = False
            vuln_queue.append("###DONE###")

    thread = threading.Thread(target=execute, daemon=True)
    thread.start()

    return jsonify({'status': 'started'})

@app.route('/logs')
@require_auth
def logs():
    def generate():
        global log_queue, vuln_queue, scanning

        sent_logs = 0
        sent_vulns = 0

        try:
            while scanning or sent_logs < len(log_queue) or sent_vulns < len(vuln_queue):
                while sent_logs < len(log_queue):
                    try:
                        yield f"data: {log_queue[sent_logs]}\n\n"
                        sent_logs += 1
                    except (BrokenPipeError, ConnectionError):
                        return

                while sent_vulns < len(vuln_queue):
                    try:
                        yield f"data: {vuln_queue[sent_vulns]}\n\n"
                        sent_vulns += 1
                    except (BrokenPipeError, ConnectionError):
                        return

                time.sleep(0.1)
        except GeneratorExit:
            return

    from flask import Response, stream_with_context
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/health', methods=['GET'])
@require_auth
def health():
    return jsonify({
        'status': 'ok',
        'scanning': scanning,
        'log_count': len(log_queue),
        'vuln_count': len(vuln_queue),
        'user': session.get('user_id')
    })

# ==================== STARTUP ====================
if __name__ == '__main__':
    if not os.path.exists(APP_SHELL_SCRIPT):
        print(f"⚠️ WARNING: {APP_SHELL_SCRIPT} not found!")
        print(f"Expected location: {SCRIPT_DIR}")

    print("=" * 60)
    print("🚀 Pentest Copilot running on http://127.0.0.1:5000")
    print("📝 Login: admin / admin123")
    print("=" * 60)

    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True, use_reloader=False)
