"""Additive, transactional migration of existing client identities."""
import secrets
import time

EXTRA_COLUMNS = {
    'paused': 'INTEGER NOT NULL DEFAULT 0',
    'deadline': 'REAL',
    'duration': 'TEXT',
    'timezone': "TEXT NOT NULL DEFAULT 'UTC'",
    'revision': 'INTEGER NOT NULL DEFAULT 0',
    'generation': 'INTEGER NOT NULL DEFAULT 0',
    'capabilities': "TEXT NOT NULL DEFAULT '[]'",
    'status_secret_hash': 'TEXT',
    'code_ciphertext': 'BLOB',
    'to_client_bytes': 'INTEGER NOT NULL DEFAULT 0',
    'from_client_bytes': 'INTEGER NOT NULL DEFAULT 0',
    'traffic_started_at': 'REAL',
}


def migrate(db):
    db.execute('BEGIN IMMEDIATE')
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version > 3:
        raise ValueError('Database created by a newer version')
    columns = {row['name'] for row in db.execute('PRAGMA table_info(clients)')}
    if version >= 2:
        if not set(EXTRA_COLUMNS) <= columns:
            raise ValueError('Incomplete database schema')
        if version == 3: return
    for name, declaration in EXTRA_COLUMNS.items():
        if name not in columns:
            db.execute(f'ALTER TABLE clients ADD COLUMN {name} {declaration}')
    db.execute('CREATE TABLE IF NOT EXISTS access_commands (client_id TEXT NOT NULL, command_id TEXT NOT NULL, request TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(client_id,command_id))')
    db.execute('CREATE TABLE IF NOT EXISTS server_metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
    if version < 2:
        db.execute('UPDATE clients SET status_secret_hash=secret_hash, traffic_started_at=? WHERE traffic_started_at IS NULL', (time.time(),))
    db.execute('INSERT OR IGNORE INTO server_metadata VALUES (?,?)', ('instance_id', '"'+secrets.token_hex(16)+'"'))
    db.execute('''CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, action TEXT NOT NULL,
        source TEXT NOT NULL, user_id TEXT, client_id TEXT, domain TEXT,
        result TEXT NOT NULL, details TEXT NOT NULL, operation_id TEXT UNIQUE)''')
    db.execute('CREATE INDEX IF NOT EXISTS audit_client ON audit_events(client_id,id)')
    db.execute('CREATE INDEX IF NOT EXISTS audit_time ON audit_events(at,id)')
    db.execute('CREATE INDEX IF NOT EXISTS audit_action ON audit_events(action,id)')
    count = db.execute('SELECT COUNT(*) FROM clients').fetchone()[0]
    if count:
        from server.app.journal import append_event
        append_event(db, action='migration', at=time.time(), details={'count':count})
    db.execute('PRAGMA user_version=3')
