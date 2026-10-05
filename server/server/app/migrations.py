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
    if version > 5:
        raise ValueError('Database created by a newer version')
    columns = {row['name'] for row in db.execute('PRAGMA table_info(clients)')}
    if version >= 2:
        if not set(EXTRA_COLUMNS) <= columns:
            raise ValueError('Incomplete database schema')
        if version >= 3:
            migrate_billing(db)
            migrate_availability(db)
            return
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
    migrate_billing(db)
    migrate_availability(db)

BILLING_COLUMNS = {
    'billing_mode': "TEXT NOT NULL DEFAULT 'free'",
    'price_kopecks': 'INTEGER NOT NULL DEFAULT 0',
    'balance_kopecks': 'INTEGER NOT NULL DEFAULT 0',
    'paid_from': 'REAL',
    'paid_until': 'REAL',
    'anchor_day': 'INTEGER',
    'billing_timezone': "TEXT NOT NULL DEFAULT 'UTC'",
    'billing_paused': 'INTEGER NOT NULL DEFAULT 0',
}


def migrate_billing(db):
    columns={row['name'] for row in db.execute('PRAGMA table_info(clients)')}
    version=db.execute('PRAGMA user_version').fetchone()[0]
    if version>=4:
        if not set(BILLING_COLUMNS)<=columns: raise ValueError('Incomplete billing schema')
        for table in ('billing_operations','billing_commands'):
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                raise ValueError('Incomplete billing schema')
        return
    for name,declaration in BILLING_COLUMNS.items():
        if name not in columns: db.execute(f'ALTER TABLE clients ADD COLUMN {name} {declaration}')
    db.execute("UPDATE clients SET billing_mode='legacy',billing_timezone=timezone WHERE deadline IS NOT NULL OR duration IS NOT NULL")
    db.execute('''CREATE TABLE IF NOT EXISTS billing_operations (
        operation_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, kind TEXT NOT NULL, at REAL NOT NULL,
        delta_kopecks INTEGER NOT NULL, balance_before INTEGER NOT NULL, balance_after INTEGER NOT NULL,
        price_kopecks INTEGER NOT NULL, paid_from REAL, paid_until REAL, actor TEXT NOT NULL, details TEXT NOT NULL)''')
    db.execute('CREATE INDEX IF NOT EXISTS billing_client ON billing_operations(client_id,at)')
    db.execute('''CREATE TABLE IF NOT EXISTS billing_commands (
        client_id TEXT NOT NULL,command_id TEXT NOT NULL,request TEXT NOT NULL,result TEXT NOT NULL,
        PRIMARY KEY(client_id,command_id))''')
    db.execute('PRAGMA user_version=4')

def migrate_availability(db):
    version=db.execute('PRAGMA user_version').fetchone()[0]
    tables=('outage_episodes','outage_entitlements','availability_checkpoint')
    if version>=5:
        for table in tables:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                raise ValueError('Incomplete availability schema')
        return
    db.execute("""CREATE TABLE IF NOT EXISTS outage_episodes (id TEXT PRIMARY KEY,started_at REAL NOT NULL,
        ended_at REAL,compensated_days INTEGER NOT NULL,state TEXT NOT NULL)""")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS outage_one_open ON outage_episodes(state) WHERE state='open'")
    db.execute("""CREATE TABLE IF NOT EXISTS outage_entitlements (episode_id TEXT NOT NULL,client_id TEXT NOT NULL,
        paid_until_at_start REAL NOT NULL,eligible INTEGER NOT NULL,PRIMARY KEY(episode_id,client_id))""")
    db.execute('CREATE TABLE IF NOT EXISTS availability_checkpoint (client_id TEXT PRIMARY KEY,paid_until REAL NOT NULL)')
    db.execute('PRAGMA user_version=5')
