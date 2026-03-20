import sqlite3
import logging
from .config import DB_PATH

logger = logging.getLogger(__name__)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS assignments
                 (group_name TEXT PRIMARY KEY, last_index INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS finding_assignments
                 (dedup_key TEXT PRIMARY KEY, group_name TEXT, username TEXT)''')
    conn.commit()
    conn.close()

def get_next_user(group_name: str, active_users: list[str]) -> str:
    if not active_users:
        return None
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT last_index FROM assignments WHERE group_name = ?", (group_name,))
    row = c.fetchone()
    
    if row is None:
        next_idx = 0
        c.execute("INSERT INTO assignments (group_name, last_index) VALUES (?, ?)", (group_name, next_idx))
    else:
        next_idx = (row[0] + 1) % len(active_users)
        c.execute("UPDATE assignments SET last_index = ? WHERE group_name = ?", (next_idx, group_name))
        
    conn.commit()
    conn.close()
    
    return active_users[next_idx]

def get_assigned_user(dedup_key: str, active_users: list[str]) -> str | None:
    if not active_users:
        return None

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM finding_assignments WHERE dedup_key = ?", (dedup_key,))
    row = c.fetchone()
    conn.close()

    if row and row[0] in active_users:
        return row[0]

    return None

def remember_assignment(dedup_key: str, group_name: str, username: str | None) -> None:
    if not username:
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO finding_assignments (dedup_key, group_name, username)
        VALUES (?, ?, ?)
        ON CONFLICT(dedup_key) DO UPDATE SET
            group_name = excluded.group_name,
            username = excluded.username
        """,
        (dedup_key, group_name, username),
    )
    conn.commit()
    conn.close()
