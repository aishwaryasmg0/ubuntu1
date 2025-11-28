import sqlite3
import os
from datetime import datetime
import uuid
from bcrypt import hashpw, checkpw, gensalt

DB_FILE = 'pentest_copilot.db'

def init_db():
    """Initialize database with all tables"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Sessions Table (tracks active sessions with session_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            logout_time TIMESTAMP,
            ip_address TEXT,
            is_active BOOLEAN DEFAULT 1,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Audit Logs Table (security tracking - login/logout history)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            session_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            status TEXT,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Scan History Table (optional - track pentests)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            vulnerabilities_found INTEGER,
            status TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # ==================== COOKIES TABLE ====================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            cookie_name TEXT NOT NULL,
            cookie_value TEXT NOT NULL,
            cookie_domain TEXT DEFAULT '127.0.0.1',
            cookie_path TEXT DEFAULT '/',
            cookie_expiry TIMESTAMP,
            cookie_httponly BOOLEAN DEFAULT 1,
            cookie_secure BOOLEAN DEFAULT 0,
            cookie_samesite TEXT DEFAULT 'Lax',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"✅ Database initialized: {DB_FILE}")

def hash_password(password):
    """Hash password with bcrypt"""
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against bcrypt hash"""
    return checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def add_user(username, password, full_name=None, email=None):
    """Add a new user to database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    password_hash = hash_password(password)
    
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash, full_name, email)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash, full_name, email))
        conn.commit()
        print(f"✅ User created: {username}")
        return True
    except sqlite3.IntegrityError:
        print(f"⚠️ User already exists: {username}")
        return False
    finally:
        conn.close()

def get_user_by_username(username):
    """Get user from database by username"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_session(user_id, session_id, ip_address):
    """Create a new session in database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    expires_at = datetime.now().timestamp() + (24 * 60 * 60)  # 24 hours
    
    cursor.execute('''
        INSERT INTO sessions (user_id, session_id, ip_address, expires_at, is_active)
        VALUES (?, ?, ?, datetime(?, 'unixepoch'), 1)
    ''', (user_id, session_id, ip_address, int(expires_at)))
    
    conn.commit()
    conn.close()

def end_session(session_id):
    """Mark session as inactive (logout)"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE sessions 
        SET is_active = 0, logout_time = CURRENT_TIMESTAMP
        WHERE session_id = ?
    ''', (session_id,))
    conn.commit()
    conn.close()

def log_audit(user_id, action, session_id, ip_address, status, details=None):
    """Log user action to audit log"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, session_id, ip_address, status, details)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, action, session_id, ip_address, status, details))
    conn.commit()
    conn.close()

def get_active_sessions():
    """Get all active sessions with user info"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            s.id,
            s.session_id,
            u.username,
            u.full_name,
            s.login_time,
            s.ip_address,
            s.is_active
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.is_active = 1
        ORDER BY s.login_time DESC
    ''')
    sessions = cursor.fetchall()
    conn.close()
    return sessions

def get_login_history():
    """Get all login history"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            a.id,
            u.username,
            a.action,
            a.timestamp,
            a.ip_address,
            a.status
        FROM audit_logs a
        JOIN users u ON a.user_id = u.id
        WHERE a.action IN ('login', 'logout')
        ORDER BY a.timestamp DESC
        LIMIT 100
    ''')
    history = cursor.fetchall()
    conn.close()
    return history

def get_all_users():
    """Get all users from database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, full_name, email, created_at, is_active FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    conn.close()
    return users

def get_session_by_id(session_id):
    """Get session details by session_id"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, u.username 
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_id = ?
    ''', (session_id,))
    session = cursor.fetchone()
    conn.close()
    return session

# ==================== COOKIE FUNCTIONS ====================
def store_cookie_in_db(user_id, session_id, cookie_name, cookie_value, cookie_expiry):
    """Store cookie details in database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO cookies 
            (user_id, session_id, cookie_name, cookie_value, cookie_expiry, cookie_domain, cookie_path, cookie_httponly, cookie_samesite)
            VALUES (?, ?, ?, ?, ?, '127.0.0.1', '/', 1, 'Lax')
        ''', (user_id, session_id, cookie_name, cookie_value, cookie_expiry))
        
        conn.commit()
        print(f"✅ Cookie stored in DB: {cookie_name} (session: {session_id[:8]}...)")
        return True
    except Exception as e:
        print(f"❌ Error storing cookie: {e}")
        return False
    finally:
        conn.close()

def get_all_cookies():
    """Get all cookies from database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            c.id,
            c.session_id,
            u.username,
            c.cookie_name,
            c.cookie_value,
            c.cookie_expiry,
            c.created_at,
            c.last_accessed,
            c.is_active
        FROM cookies c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''')
    cookies = cursor.fetchall()
    conn.close()
    return cookies

def get_cookies_by_user(user_id):
    """Get all cookies for a specific user"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM cookies 
        WHERE user_id = ? AND is_active = 1
        ORDER BY created_at DESC
    ''', (user_id,))
    cookies = cursor.fetchall()
    conn.close()
    return cookies

def get_cookie_by_session(session_id):
    """Get cookie for a specific session"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM cookies 
        WHERE session_id = ? AND is_active = 1
    ''', (session_id,))
    cookie = cursor.fetchone()
    conn.close()
    return cookie

def delete_cookie_from_db(session_id):
    """Mark cookie as inactive (delete)"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE cookies 
        SET is_active = 0
        WHERE session_id = ?
    ''', (session_id,))
    conn.commit()
    conn.close()
    print(f"✅ Cookie marked inactive in DB")

def update_cookie_access_time(session_id):
    """Update last accessed time for cookie"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE cookies 
        SET last_accessed = CURRENT_TIMESTAMP
        WHERE session_id = ?
    ''', (session_id,))
    conn.commit()
    conn.close()