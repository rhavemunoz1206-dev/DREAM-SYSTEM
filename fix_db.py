import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dream.db')
conn = sqlite3.connect(DB_PATH)

cols = [r[1] for r in conn.execute('PRAGMA table_info(packages)').fetchall()]
if 'inclusions' not in cols:
    conn.execute("ALTER TABLE packages ADD COLUMN inclusions TEXT DEFAULT '[]'")
    conn.commit()
    print('Fixed: added inclusions column to packages.')
else:
    print('Already good: inclusions column exists.')

conn.close()
print('Done!')
