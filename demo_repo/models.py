import sqlite3
import os

# Simple in-memory or file-based sqlite for demo purposes
db_path = os.path.join(os.path.dirname(__file__), 'demo.db')

def get_db():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                password TEXT,
                phone TEXT,
                dob TEXT,
                gender TEXT,
                religion TEXT,
                mother_maiden_name TEXT,
                voter_id TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                card_number VARCHAR,
                amount REAL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS kyc_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                pan_number TEXT,
                aadhaar_number TEXT,
                voter_id TEXT,
                driving_licence TEXT,
                passport_number TEXT,
                religion TEXT,
                caste TEXT
            )
        ''')
    conn.close()

init_db()
