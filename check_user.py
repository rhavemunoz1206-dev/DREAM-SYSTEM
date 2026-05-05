from dotenv import load_dotenv
import os, psycopg2, hashlib

load_dotenv()
conn = psycopg2.connect(os.getenv('DATABASE_URL'))
cur = conn.cursor()

# Show all users
cur.execute("SELECT id, username, role, password FROM users")
rows = cur.fetchall()
print("Users in database:")
for r in rows:
    print(f"  id={r[0]} username={r[1]} role={r[2]} password={r[3][:20]}...")

# Show what admin123 hashes to
expected = hashlib.sha256('admin123'.encode()).hexdigest()
print(f"\nExpected hash for 'admin123': {expected[:20]}...")

conn.close()
