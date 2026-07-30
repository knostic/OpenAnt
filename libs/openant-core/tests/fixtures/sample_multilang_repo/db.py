"""Sample database module for testing."""
import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def get_user(user_id):
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1]}
    return None


def create_user(name):
    conn = get_connection()
    cursor = conn.execute("INSERT INTO users (name) VALUES (?)", (name,))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return {"id": user_id, "name": name}
