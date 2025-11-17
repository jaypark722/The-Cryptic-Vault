import json
import os
import sqlite3
from datetime import datetime
from flask import request, session
from functools import wraps
from typing import Optional, Any, Dict


class HoneypotLogger:
    def __init__(self, db_path='honeypot_logs.db'):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the main DB and tables for web and SSH logging."""
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else '.', exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Web session tables (existing schema)
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

        # SSH-specific tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                command_count INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Ensure backward-compatible label column for supervised annotations
        # Add 'label' column if it doesn't exist (used for supervised training)
        try:
            cursor.execute("ALTER TABLE ssh_sessions ADD COLUMN label TEXT DEFAULT NULL")
        except Exception:
            # Column likely already exists or SQLite version doesn't support; ignore
            pass

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL,
                response TEXT,
                success BOOLEAN,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES ssh_sessions(session_id)
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
    
    def log_event(self, event_type: str, product_id: Optional[str]=None, additional_data: Optional[Dict[str, Any]]=None):
        """Generic web event logger (preserves original behavior)."""
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

    # SSH-specific logging helpers
    def log_ssh_connection(self, session_id: str, ip_address: str, username: str) -> None:
        """Log a new SSH connection and create a session record."""
        timestamp = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR IGNORE INTO ssh_sessions 
                (session_id, ip_address, username, start_time)
                VALUES (?, ?, ?, ?)
            ''', (session_id, ip_address, username, timestamp))
        # Also store a generic event for cross-correlation
        self._log_generic_event('SSH_CONNECTION', session_id, ip_address, {'username': username, 'timestamp': timestamp})

    def log_ssh_command(self, session_id: str, command: str, response: str, success: bool) -> None:
        """Log an SSH command and update session command count."""
        timestamp = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO ssh_commands 
                (session_id, timestamp, command, response, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, timestamp, command, response, int(bool(success))))
            conn.execute('''
                UPDATE ssh_sessions 
                SET command_count = command_count + 1 
                WHERE session_id = ?
            ''', (session_id,))
        self._log_generic_event('SSH_COMMAND', session_id, None, {'command': command, 'success': success, 'timestamp': timestamp})

    def log_ssh_session_end(self, session_id: str) -> None:
        """Mark SSH session as ended and log duration."""
        timestamp = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE ssh_sessions 
                SET end_time = ? 
                WHERE session_id = ?
            ''', (timestamp, session_id))
        duration = self.get_session_duration(session_id)
        self._log_generic_event('SSH_SESSION_END', session_id, None, {'timestamp': timestamp, 'duration': duration})

    def _log_generic_event(self, event_type: str, session_id: Optional[str], ip_address: Optional[str], data: Dict[str, Any]) -> None:
        """Helper to store events in the generic events table for cross-correlation."""
        timestamp = datetime.now()
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT INTO events (session_id, timestamp, event_type, ip_address, additional_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, timestamp, event_type, ip_address, json.dumps(data)))
        conn.commit()
        conn.close()

    def get_session_duration(self, session_id: str) -> float:
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute('''
                SELECT start_time, end_time FROM ssh_sessions 
                WHERE session_id = ?
            ''', (session_id,)).fetchone()
            if not result:
                return 0.0
            start_time = datetime.fromisoformat(result[0])
            end_time = (datetime.fromisoformat(result[1]) if result[1] else datetime.now())
            return (end_time - start_time).total_seconds()

    def get_ssh_statistics(self):
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            stats['total_sessions'] = conn.execute('SELECT COUNT(*) FROM ssh_sessions').fetchone()[0]
            stats['total_commands'] = conn.execute('SELECT COUNT(*) FROM ssh_commands').fetchone()[0]
            stats['top_usernames'] = conn.execute('''
                SELECT username, COUNT(*) as count 
                FROM ssh_sessions 
                GROUP BY username 
                ORDER BY count DESC 
                LIMIT 10
            ''').fetchall()
            stats['top_commands'] = conn.execute('''
                SELECT command, COUNT(*) as count 
                FROM ssh_commands 
                GROUP BY command 
                ORDER BY count DESC 
                LIMIT 10
            ''').fetchall()
            stats['top_ips'] = conn.execute('''
                SELECT ip_address, COUNT(*) as count 
                FROM ssh_sessions 
                GROUP BY ip_address 
                ORDER BY count DESC 
                LIMIT 10
            ''').fetchall()
            return stats

    def get_activity_profiles(self, limit=10):
        """Return combined profiling information across web and SSH activity.

        Returns a dict with top IPs, top SSH commands, top web paths, top web users,
        average events/commands per session, and counts.
        """
        with sqlite3.connect(self.db_path) as conn:
            profiles = {}
            # SSH totals
            profiles['total_ssh_sessions'] = conn.execute('SELECT COUNT(*) FROM ssh_sessions').fetchone()[0]
            profiles['total_ssh_commands'] = conn.execute('SELECT COUNT(*) FROM ssh_commands').fetchone()[0]

            # Web totals
            profiles['total_web_sessions'] = conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
            profiles['total_web_events'] = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]

            # Averages
            profiles['avg_commands_per_ssh_session'] = (profiles['total_ssh_commands'] / profiles['total_ssh_sessions']) if profiles['total_ssh_sessions'] > 0 else 0
            profiles['avg_events_per_web_session'] = (profiles['total_web_events'] / profiles['total_web_sessions']) if profiles['total_web_sessions'] > 0 else 0

            # Top IPs (combined from web and ssh)
            profiles['top_ips'] = conn.execute('''
                SELECT ip, SUM(cnt) as total FROM (
                    SELECT ip_address as ip, COUNT(*) as cnt FROM sessions GROUP BY ip_address
                    UNION ALL
                    SELECT ip_address as ip, COUNT(*) as cnt FROM ssh_sessions GROUP BY ip_address
                ) GROUP BY ip ORDER BY total DESC LIMIT ?
            ''', (limit,)).fetchall()

            # Top SSH commands
            profiles['top_ssh_commands'] = conn.execute('''
                SELECT command, COUNT(*) as count FROM ssh_commands
                GROUP BY command ORDER BY count DESC LIMIT ?
            ''', (limit,)).fetchall()

            # Top web paths
            profiles['top_web_paths'] = conn.execute('''
                SELECT path, COUNT(*) as count FROM events
                WHERE path IS NOT NULL
                GROUP BY path ORDER BY count DESC LIMIT ?
            ''', (limit,)).fetchall()

            # Top web usernames (from sessions.username)
            profiles['top_web_users'] = conn.execute('''
                SELECT username, COUNT(*) as count FROM sessions
                WHERE username IS NOT NULL AND username != ''
                GROUP BY username ORDER BY count DESC LIMIT ?
            ''', (limit,)).fetchall()

            # Top SSH usernames
            profiles['top_ssh_usernames'] = conn.execute('''
                SELECT username, COUNT(*) as count FROM ssh_sessions
                GROUP BY username ORDER BY count DESC LIMIT ?
            ''', (limit,)).fetchall()

            # Totals for downloads and purchases (from sessions table)
            profiles['total_downloads'] = conn.execute('SELECT SUM(downloads_attempted) FROM sessions').fetchone()[0] or 0
            profiles['total_purchases'] = conn.execute('SELECT SUM(purchases_made) FROM sessions').fetchone()[0] or 0

            # Top downloaded products (from events table where event_type == 'DOWNLOAD')
            profiles['top_downloaded_products'] = conn.execute('''
                SELECT product_id, COUNT(*) as count FROM events
                WHERE event_type = 'DOWNLOAD' AND product_id IS NOT NULL
                GROUP BY product_id ORDER BY count DESC LIMIT ?
            ''', (limit,)).fetchall()

            return profiles

    # SSH session retrieval methods
    def get_all_ssh_sessions(self, limit=100):
        """Get all SSH sessions with their metadata."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM ssh_sessions 
            ORDER BY start_time DESC 
            LIMIT ?
        ''', (limit,))
        sessions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return sessions
    
    def get_ssh_commands(self, session_id=None, limit=100):
        """Get SSH commands, optionally filtered by session_id."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if session_id:
            cursor.execute('''
                SELECT * FROM ssh_commands 
                WHERE session_id = ?
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (session_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM ssh_commands 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        commands = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return commands

    def label_ssh_session(self, session_id: str, label: str) -> None:
        """Annotate an ssh_session with a human-provided label for supervised training."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE ssh_sessions SET label = ? WHERE session_id = ?
            ''', (label, session_id))
        # Persist an event for auditing
        self._log_generic_event('SSH_LABEL', session_id, None, {'label': label})

    # Existing utility functions for web UI
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
            if event.get('additional_data'):
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