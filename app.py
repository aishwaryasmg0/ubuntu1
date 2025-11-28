
from flask import Flask, render_template, request, jsonify, redirect, session, send_from_directory
from flask_session import Session
import subprocess
import threading
import time
import os
import json
import uuid
from datetime import timedelta, datetime
from database import (
    init_db, get_user_by_username, verify_password, hash_password, add_user,
    create_session, end_session, log_audit, get_active_sessions,
    get_login_history, get_all_users, get_session_by_id,
    store_cookie_in_db, get_all_cookies, get_cookies_by_user,
    get_cookie_by_session, delete_cookie_from_db, update_cookie_access_time
)

app = Flask(__name__)

# ==================== SESSION CONFIGURATION ====================
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production-use-long-random-string'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_PERMANENT'] = False
Session(app)

# ==================== INITIALIZE DATABASE ====================
init_db()

# Create default users if they don't exist
DEFAULT_USERS = [
    ('admin', 'admin123', 'Admin User', 'admin@pentest.local'),
    ('pentest', 'pentest@2024', 'Pentest User', 'pentest@pentest.local'),
    ('user', 'user123', 'Regular User', 'user@pentest.local'),
]

for username, password, full_name, email in DEFAULT_USERS:
    user = get_user_by_username(username)
    if not user:
        add_user(username, password, full_name, email)

# ==================== GLOBAL VARIABLES ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_SHELL_SCRIPT = os.path.join(SCRIPT_DIR, 'app.sh')

log_queue = []
vuln_queue = []
scanning = False

# ==================== HELPER FUNCTIONS ====================
def get_client_ip():
    """Get client IP address"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

# ==================== AUTHENTICATION ROUTES ====================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    ip_address = get_client_ip()

    # Get user from DATABASE
    user = get_user_by_username(username)
    
    if not user or not verify_password(password, user['password_hash']):
        # Log failed login attempt
        log_audit(None, 'login', None, ip_address, 'FAILED', f'Username: {username}')
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        }), 401

    # ==================== CREATE SESSION ID ====================
    session_id = str(uuid.uuid4())  # Generate unique session ID
    
    # Store in Flask session
    session['user_id'] = user['username']
    session['logged_in'] = True
    session['session_id'] = session_id
    session['login_ip'] = ip_address
    session['login_time'] = time.time()
    
    # Store session in SQLite database
    create_session(user['id'], session_id, ip_address)
    
    # Log successful login
    log_audit(user['id'], 'login', session_id, ip_address, 'SUCCESS', f'User: {username}')
    
    # ==================== BUILD RESPONSE WITH COOKIE ====================
    resp = jsonify({
        'success': True,
        'message': 'Login successful',
        'redirect': '/dashboard'
    })
    
    # SET COOKIE with session_id
    resp.set_cookie(
        'pentest_session',          # cookie name
        session_id,                 # cookie value
        max_age=24 * 60 * 60,       # 24 hours
        httponly=True,              # JS cannot read it
        secure=False,               # set True when using HTTPS
        samesite='Lax',
        path='/'
    )
    
    # ==================== STORE COOKIE IN DATABASE ====================
    cookie_expiry = datetime.now() + timedelta(hours=24)
    store_cookie_in_db(
        user_id=user['id'],
        session_id=session_id,
        cookie_name='pentest_session',
        cookie_value=session_id,
        cookie_expiry=cookie_expiry
    )
    
    return resp

@app.route('/api/logout', methods=['POST'])
def logout():
    # COLLECT COOKIE before clearing session
    cookie_session = request.cookies.get('pentest_session')
    user_id = None
    session_id = session.get('session_id')
    ip_address = get_client_ip()
    username = session.get('user_id')
    
    # Get user ID for logging
    if username:
        user = get_user_by_username(username)
        if user:
            user_id = user['id']
    
    # Mark session as inactive in database
    if session_id:
        end_session(session_id)
    
    # ==================== DELETE COOKIE FROM DATABASE ====================
    if session_id:
        delete_cookie_from_db(session_id)
    
    # Log logout
    if user_id:
        log_audit(user_id, 'logout', session_id, ip_address, 'SUCCESS', f'User: {username}')
    
    # Clear Flask session
    session.clear()
    
    # ==================== BUILD RESPONSE AND DELETE COOKIE ====================
    resp = jsonify({'success': True, 'redirect': '/'})
    resp.set_cookie('pentest_session', '', max_age=0, path='/')  # delete cookie
    
    return resp

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if session.get('logged_in'):
        # ==================== SERVER COLLECTS COOKIE FROM BROWSER ====================
        cookie_session = request.cookies.get('pentest_session')
        session_id = session.get('session_id')
        
        # Update last accessed time for cookie
        if session_id:
            update_cookie_access_time(session_id)
        
        return jsonify({
            'authenticated': True,
            'user': session.get('user_id'),
            'session_id': session_id,
            'cookie_session': cookie_session  # server collected cookie
        })
    else:
        return jsonify({'authenticated': False}), 401

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/sessions', methods=['GET'])
def admin_sessions():
    """Get all active sessions (admin only)"""
    if not session.get('logged_in') or session.get('user_id') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    sessions = get_active_sessions()
    return jsonify({
        'sessions': [dict(s) for s in sessions]
    })

@app.route('/api/admin/login-history', methods=['GET'])
def admin_login_history():
    """Get login history (admin only)"""
    if not session.get('logged_in') or session.get('user_id') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    history = get_login_history()
    return jsonify({
        'history': [dict(h) for h in history]
    })

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    """Get all users (admin only)"""
    if not session.get('logged_in') or session.get('user_id') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = get_all_users()
    return jsonify({
        'users': [dict(u) for u in users]
    })

@app.route('/api/admin/cookies', methods=['GET'])
def admin_cookies():
    """Get all cookies stored in database (admin only)"""
    if not session.get('logged_in') or session.get('user_id') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    cookies = get_all_cookies()
    return jsonify({
        'cookies': [dict(c) for c in cookies]
    })

@app.route('/api/admin/user-cookies/<int:user_id>', methods=['GET'])
def admin_user_cookies(user_id):
    """Get cookies for specific user (admin only)"""
    if not session.get('logged_in') or session.get('user_id') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    cookies = get_cookies_by_user(user_id)
    return jsonify({
        'cookies': [dict(c) for c in cookies]
    })

# ==================== MIDDLEWARE ====================
def is_authenticated():
    return session.get('logged_in', False)

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return jsonify({'error': 'Unauthorized'}), 401
        
        # ==================== SERVER COLLECTS COOKIE ON EVERY REQUEST ====================
        cookie_session = request.cookies.get('pentest_session')
        server_session_id = session.get('session_id')
        
        # Optional: Verify cookie matches server session
        if cookie_session != server_session_id:
            return jsonify({'error': 'Session mismatch'}), 401
        
        # Update last accessed time for cookie
        if server_session_id:
            update_cookie_access_time(server_session_id)
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== PAGE ROUTES ====================
@app.route('/')
def login_page():
    """Show login page - FIRST ROUTE"""
    if is_authenticated():
        return redirect('/dashboard')
    
    try:
        with open(os.path.join(SCRIPT_DIR, 'login.html'), 'r') as f:
            return f.read()
    except:
        return "Error: login.html not found", 404

@app.route('/dashboard')
def dashboard():
    """Show dashboard - PROTECTED ROUTE"""
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
    # ==================== SERVER COLLECTS COOKIE ====================
    cookie_session = request.cookies.get('pentest_session')
    
    return jsonify({
        'status': 'ok',
        'scanning': scanning,
        'log_count': len(log_queue),
        'vuln_count': len(vuln_queue),
        'user': session.get('user_id'),
        'session_id': session.get('session_id'),
        'cookie_session': cookie_session
    })

# ==================== STARTUP ====================
if __name__ == '__main__':
    if not os.path.exists(APP_SHELL_SCRIPT):
        print(f"⚠️ WARNING: {APP_SHELL_SCRIPT} not found!")
        print(f"Expected location: {SCRIPT_DIR}")

    print("=" * 60)
    print("🚀 Pentest Copilot running on http://127.0.0.1:5000")
    print("📝 Default Users:")
    print("   - admin / admin123")
    print("   - pentest / pentest@2024")
    print("   - user / user123")
    print("\n💾 Database: pentest_copilot.db")
    print("🍪 Cookies: Stored in pentest_copilot.db → cookies table")
    print("\n📊 Admin Routes:")
    print("   - /api/admin/cookies → View all cookies")
    print("   - /api/admin/user-cookies/<user_id> → View user cookies")
    print("=" * 60)

    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True, use_reloader=False)