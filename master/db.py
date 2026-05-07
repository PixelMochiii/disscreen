"""SQLite-backed authentication store.

Replaces the previous users.json plaintext file. Passwords are hashed with
bcrypt; login attempts are recorded for rate limiting and audit.
"""
import os
import sqlite3
import time
from contextlib import contextmanager

import bcrypt

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.db')

# Rate limit: max attempts per IP within the window before login is refused.
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_S = 15 * 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    must_change_pw  INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_login      INTEGER
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    username      TEXT,
    attempted_at  INTEGER NOT NULL,
    success       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip, attempted_at);
"""


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db(initial_admin_password=None):
    """Create schema and seed the default 'IT' admin if the table is empty."""
    with _conn() as c:
        c.executescript(SCHEMA)
        cur = c.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            pw = initial_admin_password or 'CHANGE_ME_AT_FIRST_LOGIN'
            create_user('IT', pw, is_admin=True, must_change_pw=True)
            print("✅ Admin par défaut 'IT' créé — mot de passe à changer au 1er login.")


def _hash(pw):
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def _check(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def create_user(username, password, is_admin=False, must_change_pw=False):
    with _conn() as c:
        c.execute(
            "INSERT INTO users (username, password_hash, is_admin, must_change_pw, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, _hash(password), int(bool(is_admin)),
             int(bool(must_change_pw)), int(time.time()))
        )


def get_user(username):
    with _conn() as c:
        row = c.execute(
            "SELECT id, username, password_hash, is_admin, must_change_pw, last_login "
            "FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        return dict(row) if row else None


def list_users():
    with _conn() as c:
        rows = c.execute(
            "SELECT username, is_admin, must_change_pw, last_login, created_at "
            "FROM users ORDER BY username"
        ).fetchall()
        return [dict(r) for r in rows]


def verify_password(username, password):
    """Return user dict on success, None on failure."""
    u = get_user(username)
    if u and _check(password, u['password_hash']):
        return u
    return None


def update_password(username, new_password, clear_must_change=True):
    with _conn() as c:
        c.execute(
            "UPDATE users SET password_hash = ?, must_change_pw = ? WHERE username = ?",
            (_hash(new_password), 0 if clear_must_change else 1, username)
        )


def delete_user(username):
    with _conn() as c:
        cur = c.execute("DELETE FROM users WHERE username = ?", (username,))
        return cur.rowcount > 0


def touch_last_login(username):
    with _conn() as c:
        c.execute("UPDATE users SET last_login = ? WHERE username = ?",
                  (int(time.time()), username))


def record_attempt(ip, username, success):
    with _conn() as c:
        c.execute(
            "INSERT INTO login_attempts (ip, username, attempted_at, success) "
            "VALUES (?, ?, ?, ?)",
            (ip or '?', username or None, int(time.time()), int(bool(success)))
        )


def is_rate_limited(ip):
    """True if this IP has exceeded the failed-attempt threshold within the window."""
    cutoff = int(time.time()) - RATE_LIMIT_WINDOW_S
    with _conn() as c:
        n = c.execute(
            "SELECT COUNT(*) FROM login_attempts "
            "WHERE ip = ? AND success = 0 AND attempted_at >= ?",
            (ip or '?', cutoff)
        ).fetchone()[0]
        return n >= RATE_LIMIT_MAX_ATTEMPTS


def clear_attempts(ip):
    """Wipe failed attempts for this IP after a successful login,
    et purge les entrées plus vieilles que 30 jours pour éviter la croissance infinie."""
    cutoff = int(time.time()) - 30 * 24 * 3600
    with _conn() as c:
        c.execute("DELETE FROM login_attempts WHERE ip = ? AND success = 0", (ip or '?',))
        c.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
