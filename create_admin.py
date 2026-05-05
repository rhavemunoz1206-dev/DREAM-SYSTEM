import sqlite3, hashlib

conn = sqlite3.connect('dream.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator'
)''')
pw = hashlib.sha256('admin123'.encode()).hexdigest()
conn.execute("INSERT OR REPLACE INTO users (username, password, role) VALUES ('admin', ?, 'admin')", (pw,))
conn.commit()
conn.close()
print("Done! Admin user created in dream.db")
print("Username: admin")
print("Password: admin123")
