import os
import sqlite3

from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'test_results.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS baselines (
            test_name TEXT PRIMARY KEY,
            baseline_score REAL NOT NULL,
            recorded_at TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_name TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            status TEXT NOT NULL,
            run_at TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS category_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            max_cvss REAL NOT NULL,
            run_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_test_result(test_name, cvss_score, status):
    if cvss_score is None:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('SELECT baseline_score FROM baselines WHERE test_name = ?', (test_name,))
    if c.fetchone() is None:
        c.execute(
            'INSERT INTO baselines (test_name, baseline_score, recorded_at) VALUES (?, ?, ?)',
            (test_name, cvss_score, now)
        )
    c.execute(
        'INSERT INTO history (test_name, cvss_score, status, run_at) VALUES (?, ?, ?, ?)',
        (test_name, cvss_score, status, now)
    )
    conn.commit()
    conn.close()

def save_category_max_cvss(category, max_cvss):
    if max_cvss is None:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute(
        'INSERT INTO category_history (category, max_cvss, run_at) VALUES (?, ?, ?)',
        (category, max_cvss, now)
    )
    conn.commit()
    conn.close()


def get_category_history(category, limit=20):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            'SELECT max_cvss FROM category_history WHERE category = ? ORDER BY run_at DESC LIMIT ?',
            (category, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in reversed(rows)]
    except Exception as e:
        print(f'Warning: Could not get category history for {category}: {e}')
        return []

def get_category_baseline(category):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT max_cvss FROM category_history WHERE category = ? ORDER BY run_at ASC LIMIT 1', (category,))
        row = c.fetchone()
        conn.close()
        cat_baseline = row[0] if row else None
    except Exception as e:
        print(f'Warning: Could not get category baseline for {category}: {e}')
        cat_baseline = None
    
    return cat_baseline