import os
import sqlite3
import json
import requests

# ==========================================
# ENV VARIABLES
# ==========================================

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GIST_ID = os.environ.get("GIST_ID")

if not GITHUB_TOKEN:
    raise Exception("Missing GITHUB_TOKEN")

if not GIST_ID:
    raise Exception("Missing GIST_ID")

# ==========================================
# DATABASE
# ==========================================

DATABASE_FILE = "users.db"

def initialize_database():

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)

    conn.commit()
    conn.close()

# ==========================================
# EXPORT DATABASE
# ==========================================

def export_database():

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, password_hash, public_key, encrypted_private_key
        FROM users
    """)

    rows = cursor.fetchall()
    conn.close()

    users = []

    for r in rows:
        users.append({
            "username": r[0],
            "password_hash": r[1],
            "public_key": r[2],
            "encrypted_private_key": r[3]
        })

    return json.dumps(users, indent=4)

# ==========================================
# BACKUP TO GIST (AUTO SYNC)
# ==========================================

def backup_to_gist():

    content = export_database()

    url = f"https://api.github.com/gists/{GIST_ID}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    payload = {
        "files": {
            "backup.json": {
                "content": content
            }
        }
    }

    response = requests.patch(url, headers=headers, json=payload)

    if response.status_code == 200:
        print("✔ Backup synced to Gist")
    else:
        print("❌ Backup failed")
        print(response.text)

# ==========================================
# RESTORE FROM GIST
# ==========================================

def restore_from_gist():

    print("Checking remote backup...")

    url = f"https://api.github.com/gists/{GIST_ID}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print("Failed to load Gist")
        return

    gist = response.json()
    content = gist["files"]["backup.json"]["content"]

    users = json.loads(content)

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)

    for u in users:
        cursor.execute("""
            INSERT OR REPLACE INTO users
            (username, password_hash, public_key, encrypted_private_key)
            VALUES (?, ?, ?, ?)
        """, (
            u["username"],
            u["password_hash"],
            u["public_key"],
            u["encrypted_private_key"]
        ))

    conn.commit()
    conn.close()

    print("✔ Database restored")

# ==========================================
# ADD USER (AUTO BACKUP HERE)
# ==========================================

def add_user():

    username = input("Username: ")
    password_hash = input("Password hash: ")
    public_key = input("Public key: ")
    encrypted_private_key = input("Encrypted private key: ")

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO users
        (username, password_hash, public_key, encrypted_private_key)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        password_hash,
        public_key,
        encrypted_private_key
    ))

    conn.commit()
    conn.close()

    print("✔ User added")

    # 🔥 AUTO SYNC TO GIST EVERY TIME USER IS CREATED
    backup_to_gist()

# ==========================================
# VIEW USERS
# ==========================================

def view_users():

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, public_key FROM users")

    rows = cursor.fetchall()

    for r in rows:
        print(r)

    conn.close()

# ==========================================
# MENU
# ==========================================

def menu():

    initialize_database()
    restore_from_gist()

    while True:

        print("\n1. Add user")
        print("2. View users")
        print("3. Backup now")
        print("4. Restore now")
        print("5. Exit")

        choice = input("Choose: ")

        if choice == "1":
            add_user()

        elif choice == "2":
            view_users()

        elif choice == "3":
            backup_to_gist()

        elif choice == "4":
            restore_from_gist()

        elif choice == "5":
            break

        else:
            print("Invalid")

# ==========================================
# START
# ==========================================

if __name__ == "__main__":
    menu()
