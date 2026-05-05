from dotenv import load_dotenv
import os, psycopg2, hashlib

load_dotenv()
conn = psycopg2.connect(os.getenv('DATABASE_URL'))
cur = conn.cursor()

# Create tables if they don't exist
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator'
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    name TEXT,
    date TEXT,
    location TEXT,
    client_name TEXT,
    contact TEXT,
    package TEXT,
    package_price FLOAT DEFAULT 0,
    down_payment FLOAT DEFAULT 0,
    balance FLOAT DEFAULT 0,
    paid BOOLEAN DEFAULT FALSE,
    completed BOOLEAN DEFAULT FALSE,
    completed_at TEXT,
    booth TEXT,
    printer TEXT,
    time_start TEXT,
    time_end TEXT,
    operator TEXT,
    operators_list TEXT DEFAULT '[]',
    extensions TEXT DEFAULT '[]',
    misc_fees TEXT DEFAULT '[]',
    misc_total FLOAT DEFAULT 0,
    consumables TEXT DEFAULT '{}',
    materials TEXT DEFAULT '{}',
    has_payment_proof BOOLEAN DEFAULT FALSE,
    has_layout BOOLEAN DEFAULT FALSE
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    price FLOAT NOT NULL,
    inclusions TEXT DEFAULT '[]'
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS selections (
    id SERIAL PRIMARY KEY,
    data TEXT DEFAULT '{}'
);
""")

# Create admin account
pw_hash = hashlib.sha256('admin123'.encode()).hexdigest()
cur.execute("""
INSERT INTO users (username, password, role)
VALUES ('admin', %s, 'admin')
ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, role = EXCLUDED.role
""", (pw_hash,))

conn.commit()
conn.close()
print("Done! Tables created and admin account ready.")
print("Username: admin")
print("Password: admin123")
