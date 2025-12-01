"""SQLite database for VaultSec user management and scan tracking."""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt

# Database path
DB_PATH = Path(__file__).resolve().parents[2] / "vaultsec.db"


def get_db_path() -> Path:
    """Get the database path."""
    return DB_PATH


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Initialize the database schema."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # Scans table - links scans to users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                run_name TEXT NOT NULL,
                storage_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                targets TEXT,
                user_instructions TEXT,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        
        conn.commit()


# ============================================================================
# User Operations
# ============================================================================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_user(username: str, email: str, password: str, is_admin: bool = False) -> dict[str, Any]:
    """Create a new user."""
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    hashed_password = hash_password(password)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (id, username, email, hashed_password, is_admin, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, email, hashed_password, int(is_admin), now, now),
        )
        conn.commit()
    
    return {
        "id": user_id,
        "username": username,
        "email": email,
        "is_admin": is_admin,
        "created_at": now,
    }


def get_user_by_username(username: str) -> dict[str, Any] | None:
    """Get a user by username."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_user_by_email(email: str) -> dict[str, Any] | None:
    """Get a user by email."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    """Get a user by ID."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    """Authenticate a user by username and password."""
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


# ============================================================================
# Scan Operations
# ============================================================================

def create_scan(
    user_id: str,
    run_name: str,
    storage_id: str,
    targets: str | None = None,
    user_instructions: str | None = None,
) -> dict[str, Any]:
    """Create a new scan record."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (id, user_id, run_name, storage_id, status, targets, user_instructions, started_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, user_id, run_name, storage_id, "running", targets, user_instructions, now, now),
        )
        conn.commit()
    
    return {
        "id": scan_id,
        "user_id": user_id,
        "run_name": run_name,
        "storage_id": storage_id,
        "status": "running",
        "started_at": now,
    }


def update_scan_status(scan_id: str, status: str, completed_at: str | None = None) -> None:
    """Update scan status."""
    with get_db() as conn:
        cursor = conn.cursor()
        if completed_at:
            cursor.execute(
                "UPDATE scans SET status = ?, completed_at = ? WHERE id = ?",
                (status, completed_at, scan_id),
            )
        else:
            cursor.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status, scan_id),
            )
        conn.commit()


def get_scan_by_id(scan_id: str) -> dict[str, Any] | None:
    """Get a scan by ID."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_scan_by_storage_id(storage_id: str) -> dict[str, Any] | None:
    """Get a scan by storage_id (run folder name)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE storage_id = ?", (storage_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_user_scans(user_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Get all scans for a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
            """,
            (user_id, limit),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_user_running_scan(user_id: str) -> dict[str, Any] | None:
    """Get the currently running scan for a user, if any."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scans WHERE user_id = ? AND status = 'running' LIMIT 1",
            (user_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def user_owns_scan(user_id: str, storage_id: str) -> bool:
    """Check if a user owns a scan by storage_id."""
    scan = get_scan_by_storage_id(storage_id)
    if not scan:
        return False
    return scan["user_id"] == user_id
