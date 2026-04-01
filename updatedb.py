# update_db.py
import sqlite3
import os
from datetime import datetime, timedelta

def add_column_to_uploads():
    db_path = 'instance/agent_system.db'
    
    if not os.path.exists(db_path):
        print("Database file not found. Creating new database...")
        return
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute("PRAGMA table_info(uploads)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'column_mapping' not in columns:
            print("Adding column_mapping column to uploads table...")
            cursor.execute("ALTER TABLE uploads ADD COLUMN column_mapping TEXT")
            conn.commit()
            print("Column added successfully!")
        else:
            print("column_mapping column already exists.")
        
        conn.close()
        
    except Exception as e:
        print(f"Error updating database: {e}")

def add_admin_security_tables():
    """Create pending_login_approvals table and add system settings."""
    db_path = 'instance/agent_system.db'
    
    if not os.path.exists(db_path):
        print("Database file not found. Creating new database...")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 1. Create pending_login_approvals table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_login_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_user_id INTEGER NOT NULL,
                device_fingerprint VARCHAR(64) NOT NULL,
                ip_address VARCHAR(45),
                location VARCHAR(200),
                user_agent TEXT,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                approval_token VARCHAR(64) UNIQUE NOT NULL,
                approved_by_user_id INTEGER,
                approved_at DATETIME,
                notes TEXT,
                FOREIGN KEY (admin_user_id) REFERENCES users(id),
                FOREIGN KEY (approved_by_user_id) REFERENCES users(id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_login_approvals_token ON pending_login_approvals(approval_token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_login_approvals_status ON pending_login_approvals(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_login_approvals_expires ON pending_login_approvals(expires_at)")
        
        # 2. Insert default system settings if they don't exist
        settings = [
            ('admin_security_enabled', 'true'),
            ('system_lockout', 'false'),
            ('telegram_bot_token', ''),
            ('telegram_approval_chat_id', '')
        ]
        
        for key, default_val in settings:
            cursor.execute("SELECT key FROM system_settings WHERE key = ?", (key,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, default_val, datetime.utcnow())
                )
                print(f"Added system setting: {key} = {default_val}")
            else:
                print(f"System setting {key} already exists.")
        
        conn.commit()
        conn.close()
        print("Admin security tables and settings added successfully!")
        
    except Exception as e:
        print(f"Error adding admin security tables: {e}")

if __name__ == '__main__':
    add_column_to_uploads()
    add_admin_security_tables()