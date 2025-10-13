import sqlite3
import json
import os
from datetime import datetime
from flask import request, session
from functools import wraps

class HoneypotLogger:
    def __init__(self, db_path='honeypot_logs.db'):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else '.', exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                ip_address TEXT,
                user_agent TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                total_events INTEGER DEFAULT 0,
                registered BOOLEAN DEFAULT 0,
                logged_in BOOLEAN DEFAULT 0,
                username TEXT,
                purchases_made INTEGER DEFAULT 0,
                downloads_attempted INTEGER DEFAULT 0,
                pgp_submitted BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TIMESTAMP,
                event_type TEXT,
                ip_address TEXT,
                user_agent TEXT,
                path TEXT,
                method TEXT,
                username TEXT,
                product_id TEXT,
                additional_data TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_session_id(self):
        if 'honeypot_session_id' not in session:
            import uuid
            session['honeypot_session_id'] = str(uuid.uuid4())
            session.permanent = True
        return session['honeypot_session_id']
    
    def log_event(self, event_type, product_id=None, additional_data=None):
        session_id = self.get_session_id()
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        path = request.path
        method = request.method
        username = session.get('username', None)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR IGNORE INTO sessions 
            (session_id, ip_address, user_agent, first_seen, last_seen, total_events)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (session_id, ip_address, user_agent, datetime.now(), datetime.now()))
        
        cursor.execute('''
            UPDATE sessions 
            SET last_seen = ?, 
                total_events = total_events + 1,
                logged_in = CASE WHEN ? IS NOT NULL THEN 1 ELSE logged_in END,
                username = COALESCE(?, username)
            WHERE session_id = ?
        ''', (datetime.now(), username, username, session_id))
        
        if event_type == 'REGISTER':
            cursor.execute('''
                UPDATE sessions 
                SET registered = 1 
                WHERE session_id = ?
            ''', (session_id,))
        
        if event_type == 'PURCHASE':
            cursor.execute('''
                UPDATE sessions 
                SET purchases_made = purchases_made + 1 
                WHERE session_id = ?
            ''', (session_id,))
        
        if event_type == 'DOWNLOAD':
            cursor.execute('''
                UPDATE sessions 
                SET downloads_attempted = downloads_attempted + 1 
                WHERE session_id = ?
            ''', (session_id,))
        
        if event_type == 'PGP_VERIFIED':
            cursor.execute('''
                UPDATE sessions 
                SET pgp_submitted = 1 
                WHERE session_id = ?
            ''', (session_id,))
        
        cursor.execute('''
            INSERT INTO events 
            (session_id, timestamp, event_type, ip_address, user_agent, path, method, username, product_id, additional_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, datetime.now(), event_type, ip_address, user_agent, 
              path, method, username, product_id, json.dumps(additional_data) if additional_data else None))
        
        conn.commit()
        conn.close()
    
    def get_session_stats(self, session_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
        session_data = cursor.fetchone()
        
        conn.close()
        
        if session_data:
            return dict(session_data)
        return None
    
    def get_all_sessions(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM sessions 
            ORDER BY last_seen DESC 
            LIMIT ?
        ''', (limit,))
        
        sessions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return sessions
    
    def get_all_events(self, session_id=None, limit=100):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if session_id:
            cursor.execute('''
                SELECT * FROM events 
                WHERE session_id = ?
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (session_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM events 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        
        events = []
        for row in cursor.fetchall():
            event = dict(row)
            if event['additional_data']:
                try:
                    event['additional_data'] = json.loads(event['additional_data'])
                except:
                    pass
            events.append(event)
        
        conn.close()
        return events
    
    def export_logs_json(self, output_file='honeypot_export.json'):
        sessions = self.get_all_sessions(limit=10000)
        events = self.get_all_events(limit=10000)
        
        export_data = {
            'export_date': datetime.now().isoformat(),
            'sessions': sessions,
            'events': events
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return output_file


def log_page_view(logger):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logger.log_event('PAGE_VIEW', additional_data={
                'page': request.endpoint
            })
            return f(*args, **kwargs)
        return decorated_function
    return decorator