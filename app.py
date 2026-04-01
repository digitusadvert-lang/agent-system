# app.py - Production-ready for Render
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import os
import json
import re
import secrets
from functools import wraps
import uuid
import logging
import requests as http_req
from logging.handlers import RotatingFileHandler
import requests
import threading
import time

# Initialize Flask app
app = Flask(__name__)

# ==================== PRODUCTION ENVIRONMENT DETECTION ====================
IS_RENDER = os.environ.get('RENDER', False)
IS_PRODUCTION = IS_RENDER or os.environ.get('PRODUCTION', False)

# ==================== CUSTOM JINJA2 FILTERS ====================
def from_json(value):
    """Parse JSON string to Python object"""
    try:
        return json.loads(value) if value else {}
    except:
        return {}

# Register custom filters
app.jinja_env.filters['from_json'] = from_json

# ==================== CONFIGURATION ====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database configuration - use PostgreSQL on Render, SQLite locally
if IS_RENDER:
    # Use PostgreSQL if DATABASE_URL is provided
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Fix for Render PostgreSQL URLs (sometimes start with postgres://)
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        }
        print(f"[CONFIG] Using PostgreSQL database")
    else:
        # Fallback to SQLite in /tmp (temporary - data will be lost on restart)
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/agent_system.db'
        print(f"[CONFIG] Using SQLite in /tmp (temporary storage)")
else:
    # Local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///agent_system.db'
    print(f"[CONFIG] Using local SQLite database")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload configuration - use /tmp on Render for temporary storage
if IS_RENDER:
    app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
    logs_dir = '/tmp/logs'
else:
    app.config['UPLOAD_FOLDER'] = 'uploads'
    logs_dir = 'logs'

app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(logs_dir, exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Setup logging
file_handler = RotatingFileHandler(os.path.join(logs_dir, 'agent_system.log'), maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# ==================== DATABASE MODELS ====================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    login_logs = db.relationship('LoginLog', backref='user', lazy=True)
    search_logs = db.relationship('SearchLog', backref='user', lazy=True)
    
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    must_change_password = db.Column(db.Boolean, default=False)
    credit_balance = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.must_change_password = False

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_password_expired(self):
        policy = SystemSettings.get('password_expiry_days')
        if not policy or int(policy) == 0:
            return False
        expiry_days = int(policy)
        if not self.password_changed_at:
            return True
        return (datetime.utcnow() - self.password_changed_at).days >= expiry_days

class CustomerData(db.Model):
    __tablename__ = 'customer_data'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    contact_number = db.Column(db.String(50), index=True)
    ic_number = db.Column(db.String(50), index=True)
    address = db.Column(db.Text)
    email = db.Column(db.String(120))
    additional_data = db.Column(db.Text)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    upload = db.relationship('Upload', backref='customers')

class Upload(db.Model):
    __tablename__ = 'uploads'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    row_count = db.Column(db.Integer)
    column_count = db.Column(db.Integer)
    columns_found = db.Column(db.Text)
    column_mapping = db.Column(db.Text, default='{}')
    year = db.Column(db.Integer)
    is_current = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='pending')
    
    admin = db.relationship('User', backref='uploads')

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(200))
    device_info = db.Column(db.String(500))
    connection_type = db.Column(db.String(50))
    session_duration = db.Column(db.Integer)
    session_id = db.Column(db.String(100), unique=True)

class SearchLog(db.Model):
    __tablename__ = 'search_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    search_term = db.Column(db.String(200))
    search_type = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_count = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    screenshot_taken = db.Column(db.Boolean, default=False)
    data_downloaded = db.Column(db.Boolean, default=False)

class ScreenshotLog(db.Model):
    __tablename__ = 'screenshot_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    search_log_id = db.Column(db.Integer, db.ForeignKey('search_logs.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    screenshot_path = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))

class DataDownloadLog(db.Model):
    __tablename__ = 'data_download_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    search_log_id = db.Column(db.Integer, db.ForeignKey('search_logs.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    download_format = db.Column(db.String(20))
    ip_address = db.Column(db.String(45))

class CreditLog(db.Model):
    __tablename__ = 'credit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    balance_after = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(200))
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])
    admin = db.relationship('User', foreign_keys=[admin_id])

class DuplicateRecordLog(db.Model):
    __tablename__ = 'duplicate_records_log'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'))
    existing_customer_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'))
    duplicate_data = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action_taken = db.Column(db.String(50))
    resolution_time = db.Column(db.DateTime)

class SystemSettings(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def get(key, default=None):
        s = SystemSettings.query.filter_by(key=key).first()
        return s.value if s else default

    @staticmethod
    def set(key, value):
        s = SystemSettings.query.filter_by(key=key).first()
        if s:
            s.value = str(value)
        else:
            db.session.add(SystemSettings(key=key, value=str(value)))
        db.session.commit()

class AdminDevice(db.Model):
    __tablename__ = 'admin_devices'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45))
    label = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id], backref='admin_devices')

class AdminLoginApproval(db.Model):
    __tablename__ = 'admin_login_approvals'

    id = db.Column(db.Integer, primary_key=True)
    approval_token = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fingerprint = db.Column(db.String(64))
    ip_address = db.Column(db.String(45))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    telegram_message_id = db.Column(db.Integer)

    user = db.relationship('User', foreign_keys=[user_id])

class AgentDevice(db.Model):
    __tablename__ = 'agent_devices'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45))
    label = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime)

    user = db.relationship('User', foreign_keys=[user_id], backref='devices')

class PendingLoginApproval(db.Model):
    __tablename__ = 'pending_login_approvals'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_fingerprint = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(200))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    approval_token = db.Column(db.String(64), unique=True, nullable=False)
    approved_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    admin_user = db.relationship('User', foreign_keys=[admin_user_id], backref='pending_login_approvals')
    approved_by_user = db.relationship('User', foreign_keys=[approved_by_user_id])
    
    def __repr__(self):
        return f'<PendingLoginApproval {self.id} {self.status}>'

# ==================== HELPER FUNCTIONS ====================

def calc_download_cost(row_count):
    """Return credit cost based on number of rows: 1–10."""
    if row_count <= 10:   return 1
    if row_count <= 50:   return 2
    if row_count <= 150:  return 3
    if row_count <= 300:  return 4
    if row_count <= 500:  return 5
    if row_count <= 750:  return 6
    if row_count <= 1000: return 7
    if row_count <= 1500: return 8
    if row_count <= 2000: return 9
    return 10

def search_by_ic(term):
    """Search IC number tolerantly — with or without dashes."""
    clean = term.replace('-', '').replace(' ', '')
    results = CustomerData.query.filter(CustomerData.ic_number.ilike(f'%{term}%')).all()
    if results:
        return results
    all_customers = CustomerData.query.filter(CustomerData.ic_number != '').all()
    return [c for c in all_customers if c.ic_number.replace('-', '').replace(' ', '') == clean]

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr
    return ip

def check_admin_device(user_id, fingerprint, ip_address):
    """Returns 'trusted', 'new', 'pending', or 'blocked'."""
    device = AdminDevice.query.filter_by(user_id=user_id, fingerprint=fingerprint).first()
    if device:
        device.last_seen = datetime.utcnow()
        device.ip_address = ip_address
        db.session.commit()
        return device.status
    else:
        new_device = AdminDevice(
            user_id=user_id,
            fingerprint=fingerprint,
            ip_address=ip_address,
            label=f'Device from {ip_address}',
            status='pending'
        )
        db.session.add(new_device)
        db.session.commit()
        return 'new'

def is_admin_security_enabled():
    return SystemSettings.get('telegram_approval_enabled', '0') == '1'

def create_pending_login_approval(user_id, fingerprint, ip_address, user_agent):
    approval = AdminLoginApproval(
        approval_token=secrets.token_hex(14),
        user_id=user_id,
        fingerprint=fingerprint,
        ip_address=ip_address,
        status='pending',
        expires_at=datetime.utcnow() + timedelta(minutes=30)
    )
    db.session.add(approval)
    db.session.commit()
    return approval

def send_telegram_notification(approval):
    return tg_send_approval_request(approval)

def tg_send_approval_request(approval):
    """Send Telegram message to boss with Approve/Decline buttons."""
    token = SystemSettings.get('telegram_bot_token')
    chat_id = SystemSettings.get('telegram_boss_chat_id')
    print(f"[TELEGRAM] token={'SET' if token else 'MISSING'} chat_id={'SET' if chat_id else 'MISSING'} enabled={SystemSettings.get('telegram_approval_enabled','0')}")
    if not token or not chat_id:
        print("[TELEGRAM] Skipping — bot token or chat ID not configured")
        return False
    try:
        text = (
            f"🚨 *Admin Login Alert*\n\n"
            f"*{approval.user.full_name}* is attempting to login from an *unrecognised device*.\n\n"
            f"📍 IP Address: `{approval.ip_address}`\n"
            f"🕐 Request expires in *30 minutes*.\n\n"
            f"Please approve or decline this login request."
        )
        keyboard = {"inline_keyboard": [[
            {"text": "✅ Approve", "callback_data": f"approve_{approval.approval_token}"},
            {"text": "❌ Decline", "callback_data": f"decline_{approval.approval_token}"}
        ]]}
        resp = http_req.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text,
                  "parse_mode": "Markdown", "reply_markup": keyboard},
            timeout=10
        )
        print(f"[TELEGRAM] API response: {resp.status_code} {resp.text[:200]}")
        if resp.ok:
            approval.telegram_message_id = resp.json()['result']['message_id']
            db.session.commit()
        return resp.ok
    except Exception as e:
        print(f"[TELEGRAM] Exception: {e}")
        app.logger.error(f"Telegram send error: {e}")
        return False

def tg_edit_message(chat_id, message_id, text):
    """Edit a Telegram message after action taken."""
    token = SystemSettings.get('telegram_bot_token')
    if not token:
        return
    try:
        http_req.post(
            f"https://api.telegram.org/bot{token}/editMessageText",
            json={"chat_id": chat_id, "message_id": message_id,
                  "text": text, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception as e:
        app.logger.error(f"Telegram edit error: {e}")

def tg_answer_callback(callback_id, text):
    token = SystemSettings.get('telegram_bot_token')
    if not token:
        return
    try:
        http_req.post(
            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
            json={"callback_query_id": callback_id, "text": text},
            timeout=10
        )
    except Exception:
        pass

def check_device_trusted(user_id, fingerprint, ip_address):
    """
    Returns 'approved', 'pending', 'blocked', or 'new'.
    Also registers unseen devices as 'pending' automatically.
    """
    device = AgentDevice.query.filter_by(user_id=user_id, fingerprint=fingerprint).first()
    if device:
        device.last_seen = datetime.utcnow()
        device.ip_address = ip_address
        db.session.commit()
        return device.status
    else:
        new_device = AgentDevice(
            user_id=user_id,
            fingerprint=fingerprint,
            ip_address=ip_address,
            label=f'Device from {ip_address}',
            status='pending'
        )
        db.session.add(new_device)
        db.session.commit()
        return 'new'

def get_location_from_ip(ip):
    try:
        return "Location lookup not implemented"
    except:
        return "Unknown"

def detect_connection_type(user_agent):
    user_agent_lower = user_agent.lower()
    if 'mobile' in user_agent_lower or 'android' in user_agent_lower or 'iphone' in user_agent_lower:
        return 'mobile'
    return 'wifi'

def clean_data_value(value):
    if pd.isna(value):
        return ''
    
    value_str = str(value).strip()
    value_str = ' '.join(value_str.split())
    
    if value_str.lower() in ['null', 'none', 'nan', 'n/a', '']:
        return ''
    
    return value_str

def detect_columns_by_content(df):
    """
    Detect columns by analyzing the actual data content
    """
    found_columns = {}
    
    for idx, col in enumerate(df.columns):
        sample_data = df[col].dropna().head(20).astype(str)
        
        if len(sample_data) == 0:
            continue
        
        ic_pattern = re.compile(r'^\d{6}-\d{2}-\d{4}$|^\d{12}$|^\d{6}\d{2}\d{4}$')
        ic_count = sum(1 for val in sample_data if ic_pattern.match(re.sub(r'[^0-9]', '', val)))
        
        phone_pattern = re.compile(r'^\+?\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}$|^\d{9,11}$')
        phone_count = sum(1 for val in sample_data if phone_pattern.match(re.sub(r'[^0-9+]', '', val)))
        
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        email_count = sum(1 for val in sample_data if email_pattern.match(val))
        
        address_count = sum(1 for val in sample_data if len(val) > 20 and ' ' in val and any(c.isdigit() for c in val))
        
        name_count = sum(1 for val in sample_data if re.match(r'^[A-Za-z\s]+$', val) and len(val.split()) >= 2 and len(val) < 50)
        
        if ic_count > len(sample_data) * 0.3 and 'ic_number' not in found_columns:
            found_columns['ic_number'] = col
        elif phone_count > len(sample_data) * 0.3 and 'contact_number' not in found_columns:
            found_columns['contact_number'] = col
        elif email_count > len(sample_data) * 0.3 and 'email' not in found_columns:
            found_columns['email'] = col
        elif address_count > len(sample_data) * 0.3 and 'address' not in found_columns:
            found_columns['address'] = col
        elif name_count > len(sample_data) * 0.3 and 'name' not in found_columns:
            found_columns['name'] = col
    
    return found_columns

def read_excel_file(file_path):
    """
    Read Excel file. Always reads the raw first row to recover actual column titles,
    replacing any pandas-generated 'Unnamed: X' with whatever is in that cell.
    """
    try:
        df_raw = pd.read_excel(file_path, header=None, engine='openpyxl')
    except:
        try:
            df_raw = pd.read_excel(file_path, header=None, engine='xlrd')
        except:
            df_raw = pd.read_excel(file_path, header=None)

    first_row = df_raw.iloc[0].astype(str)
    header_keywords = ['name', 'ic', 'phone', 'address', 'email', 'contact', 'id', 'no', 'nama', 'telefon']
    header_count = sum(1 for val in first_row if str(val).lower().strip() in header_keywords)
    text_count = sum(1 for val in first_row if re.match(r'^[A-Za-z\s]+$', str(val)) and len(str(val)) < 30)
    has_header = header_count > 2 or text_count > len(first_row) * 0.5

    if has_header:
        df = pd.read_excel(file_path, engine='openpyxl')
        new_cols = []
        for i, col in enumerate(df.columns):
            if str(col).startswith('Unnamed:'):
                raw_val = str(df_raw.iloc[0, i]).strip()
                if raw_val and raw_val.lower() not in ['nan', 'none', '']:
                    new_cols.append(raw_val)
                else:
                    new_cols.append(f'Column_{i}')
            else:
                new_cols.append(str(col))
        df.columns = new_cols
    else:
        df = df_raw.copy()
        col_names = []
        for i, val in enumerate(df_raw.iloc[0]):
            val_str = str(val).strip()
            if val_str and val_str.lower() not in ['nan', 'none', '']:
                col_names.append(val_str)
            else:
                col_names.append(f'Column_{i}')
        df.columns = col_names
        df = df.iloc[1:].reset_index(drop=True)

    return df, has_header

def process_uploaded_file_with_mapping(file_path, admin_id, manual_mapping=None, extra_columns=None):
    """
    Process file with optional manual column mapping.
    """
    try:
        df, has_header = read_excel_file(file_path)
        
        if manual_mapping:
            columns_mapping = manual_mapping
        else:
            columns_mapping = detect_columns_by_content(df)
        
        required_fields = ['name', 'contact_number', 'ic_number']
        missing_fields = [field for field in required_fields if field not in columns_mapping]
        
        if missing_fields:
            return {
                'success': False,
                'needs_manual_mapping': True,
                'available_columns': list(df.columns),
                'file_path': file_path,
                'filename': os.path.basename(file_path),
                'detected_mapping': columns_mapping,
                'preview_data': df.head(5).to_dict('records')
            }
        
        for field, col_name in columns_mapping.items():
            if col_name in df.columns:
                df[col_name] = df[col_name].apply(clean_data_value)
        
        upload = Upload(
            filename=os.path.basename(file_path),
            file_path=file_path,
            admin_id=admin_id,
            row_count=len(df),
            column_count=len(df.columns),
            columns_found=json.dumps(columns_mapping),
            column_mapping=json.dumps(columns_mapping),
            year=datetime.now().year,
            status='pending'
        )
        db.session.add(upload)
        db.session.flush()
        
        duplicates = []
        for idx, row in df.iterrows():
            ic_number = clean_data_value(row[columns_mapping.get('ic_number')]) if 'ic_number' in columns_mapping else ''
            contact_number = clean_data_value(row[columns_mapping.get('contact_number')]) if 'contact_number' in columns_mapping else ''
            
            if ic_number or contact_number:
                conditions = []
                if ic_number:
                    conditions.append(CustomerData.ic_number == ic_number)
                if contact_number:
                    conditions.append(CustomerData.contact_number == contact_number)
                
                if conditions:
                    existing = CustomerData.query.filter(or_(*conditions)).first()
                    if existing:
                        row_dict = {col: clean_data_value(val) for col, val in row.items()}
                        duplicates.append({
                            'row': idx,
                            'existing_id': existing.id,
                            'new_data': row_dict,
                            'match_type': 'IC' if (ic_number and existing.ic_number == ic_number) else 'Phone'
                        })
        
        if duplicates:
            for dup in duplicates:
                duplicate_log = DuplicateRecordLog(
                    upload_id=upload.id,
                    existing_customer_id=dup['existing_id'],
                    duplicate_data=json.dumps(dup['new_data']),
                    timestamp=datetime.utcnow(),
                    action_taken='pending'
                )
                db.session.add(duplicate_log)
            
            db.session.commit()
            return {
                'success': False,
                'needs_review': True,
                'duplicate_count': len(duplicates),
                'upload_id': upload.id,
                'message': f"Found {len(duplicates)} duplicate records. Please review."
            }
        
        customers_inserted = 0
        errors = []
        
        for idx, row in df.iterrows():
            try:
                customer = CustomerData(
                    name=clean_data_value(row[columns_mapping.get('name')]) if 'name' in columns_mapping else '',
                    contact_number=clean_data_value(row[columns_mapping.get('contact_number')]) if 'contact_number' in columns_mapping else '',
                    ic_number=clean_data_value(row[columns_mapping.get('ic_number')]) if 'ic_number' in columns_mapping else '',
                    address=clean_data_value(row[columns_mapping.get('address')]) if 'address' in columns_mapping else '',
                    email=clean_data_value(row[columns_mapping.get('email')]) if 'email' in columns_mapping else '',
                    additional_data=json.dumps(
                        {extra_columns[col]: clean_data_value(row[col]) for col in df.columns
                         if col not in columns_mapping.values() and col in extra_columns}
                        if extra_columns is not None else
                        {col: clean_data_value(row[col]) for col in df.columns if col not in columns_mapping.values()}
                    ),
                    upload_id=upload.id
                )
                
                if not any([customer.name, customer.ic_number, customer.contact_number]):
                    errors.append(f"Row {idx + 2}: Empty row, skipped")
                elif not customer.name and not customer.ic_number:
                    errors.append(f"Row {idx + 2}: Missing both name and IC, skipped")
                else:
                    db.session.add(customer)
                    customers_inserted += 1
                    
            except Exception as e:
                errors.append(f"Row {idx + 2}: {str(e)}")
        
        upload.status = 'processed'
        db.session.commit()
        
        return {
            'success': True,
            'records_inserted': customers_inserted,
            'errors': errors,
            'upload_id': upload.id,
            'message': f"Successfully inserted {customers_inserted} records."
        }
        
    except Exception as e:
        app.logger.error(f"Error processing file: {str(e)}")
        db.session.rollback()
        return {'success': False, 'error': str(e)}

def sync_file_with_mapping(file_path, admin_id, manual_mapping, extra_columns=None):
    """
    Sync a new file against existing DB records.
    """
    try:
        df, _ = read_excel_file(file_path)

        updated = 0
        inserted = 0
        unchanged = 0
        errors = []

        upload = Upload(
            filename=os.path.basename(file_path),
            file_path=file_path,
            admin_id=admin_id,
            row_count=len(df),
            column_count=len(df.columns),
            columns_found=json.dumps(manual_mapping),
            column_mapping=json.dumps(manual_mapping),
            year=datetime.now().year,
            status='synced'
        )
        db.session.add(upload)
        db.session.flush()

        for idx, row in df.iterrows():
            try:
                new_name    = clean_data_value(row[manual_mapping['name']]) if 'name' in manual_mapping else ''
                new_contact = clean_data_value(row[manual_mapping['contact_number']]) if 'contact_number' in manual_mapping else ''
                new_ic      = clean_data_value(row[manual_mapping['ic_number']]) if 'ic_number' in manual_mapping else ''
                new_address = clean_data_value(row[manual_mapping['address']]) if 'address' in manual_mapping else ''
                new_email   = clean_data_value(row[manual_mapping['email']]) if 'email' in manual_mapping else ''

                if not new_name and not new_ic and not new_contact:
                    continue

                if extra_columns is not None:
                    new_extra = {label: clean_data_value(row[col]) for col, label in extra_columns.items() if col in df.columns}
                else:
                    new_extra = {col: clean_data_value(row[col]) for col in df.columns if col not in manual_mapping.values()}

                existing = None
                if new_ic:
                    existing = CustomerData.query.filter_by(ic_number=new_ic).first()
                if not existing and new_contact:
                    existing = CustomerData.query.filter_by(contact_number=new_contact).first()

                if existing:
                    changed = False
                    if new_name and existing.name != new_name:
                        existing.name = new_name; changed = True
                    if new_contact and existing.contact_number != new_contact:
                        existing.contact_number = new_contact; changed = True
                    if new_ic and existing.ic_number != new_ic:
                        existing.ic_number = new_ic; changed = True
                    if new_address and existing.address != new_address:
                        existing.address = new_address; changed = True
                    if new_email and existing.email != new_email:
                        existing.email = new_email; changed = True
                    if new_extra:
                        existing_extra = json.loads(existing.additional_data) if existing.additional_data else {}
                        merged = {**existing_extra, **{k: v for k, v in new_extra.items() if v}}
                        if merged != existing_extra:
                            existing.additional_data = json.dumps(merged); changed = True
                    if changed:
                        existing.updated_at = datetime.utcnow()
                        updated += 1
                    else:
                        unchanged += 1
                else:
                    customer = CustomerData(
                        name=new_name,
                        contact_number=new_contact,
                        ic_number=new_ic,
                        address=new_address,
                        email=new_email,
                        additional_data=json.dumps(new_extra),
                        upload_id=upload.id
                    )
                    db.session.add(customer)
                    inserted += 1

            except Exception as e:
                errors.append(f"Row {idx + 2}: {str(e)}")

        db.session.commit()
        return {
            'success': True,
            'updated': updated,
            'inserted': inserted,
            'unchanged': unchanged,
            'errors': errors,
            'upload_id': upload.id
        }

    except Exception as e:
        app.logger.error(f"Sync error: {str(e)}")
        db.session.rollback()
        return {'success': False, 'error': str(e)}

# ==================== DECORATORS ====================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== SECURITY HELPERS ====================

def is_system_locked():
    """Return True if system lockout is active."""
    return SystemSettings.get('system_locked', '0') == '1'

# ==================== ROUTES ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def enforce_password_policy():
    open_routes = {'login', 'logout', 'force_change_password', 'static',
                   'waiting_approval', 'check_approval', 'telegram_webhook', 'system_locked_page', 'health'}

    if request.endpoint not in open_routes:
        if SystemSettings.get('system_locked', '0') == '1':
            if not current_user.is_authenticated:
                return redirect(url_for('system_locked_page'))
            if request.endpoint != 'unlock_system' and current_user.role != 'admin':
                return redirect(url_for('system_locked_page'))

    if current_user.is_authenticated and request.endpoint not in open_routes:
        if session.get('force_pw_change') or current_user.is_password_expired() or current_user.must_change_password:
            session['force_pw_change'] = True
            return redirect(url_for('force_change_password'))

@app.context_processor
def inject_globals():
    try:
        from flask_login import current_user
        if current_user.is_authenticated and current_user.role == 'admin':
            count = AgentDevice.query.filter_by(status='pending').count()
            phase2 = SystemSettings.get('phase2_enabled', '0') == '1'
            return {'pending_devices_count': count, 'phase2_enabled': phase2}
    except:
        pass
    return {'pending_devices_count': 0, 'phase2_enabled': False}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_system_locked():
        flash('System is temporarily locked due to security review. Please contact the administrator.', 'danger')
        return redirect(url_for('system_locked_page'))
    
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('agent_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            ip_address = get_client_ip()
            user_agent = request.headers.get('User-Agent', '')
            connection_type = detect_connection_type(user_agent)
            session_id = str(uuid.uuid4())
            fingerprint = request.form.get('fp', '')

            if user.role == 'admin' and fingerprint and is_admin_security_enabled():
                admin_status = check_admin_device(user.id, fingerprint, ip_address)
                session['admin_device_status'] = admin_status
                
                if admin_status == 'blocked':
                    flash('Access denied: this device is blocked.', 'danger')
                    return redirect(url_for('login'))
                
                if admin_status in ('new', 'pending'):
                    pending = create_pending_login_approval(
                        user.id, fingerprint, ip_address, user_agent
                    )
                    send_telegram_notification(pending)
                    session['pending_approval_token'] = pending.approval_token
                    return redirect(url_for('waiting_approval'))
            
            login_log = LoginLog(
                user_id=user.id,
                ip_address=ip_address,
                location=get_location_from_ip(ip_address),
                device_info=user_agent,
                connection_type=connection_type,
                session_id=session_id
            )
            db.session.add(login_log)
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user)
            session['login_log_id'] = login_log.id
            session['session_id'] = session_id

            if user.is_password_expired() or user.must_change_password:
                session['force_pw_change'] = True
                flash('Your password has expired. Please set a new password.', 'warning')
                return redirect(url_for('force_change_password'))

            if user.role == 'admin' and fingerprint and not is_admin_security_enabled():
                admin_status = check_admin_device(user.id, fingerprint, ip_address)
                session['admin_device_status'] = admin_status
                if admin_status in ('new', 'pending'):
                    flash(f'Warning: Unrecognised device detected from {ip_address}. This login has been flagged.', 'warning')
                elif admin_status == 'blocked':
                    logout_user()
                    flash('Access denied: this device is blocked.', 'danger')
                    return redirect(url_for('login'))

            flash(f'Welcome back, {user.full_name}!', 'success')

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('agent_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if 'login_log_id' in session:
        login_log = LoginLog.query.get(session['login_log_id'])
        if login_log:
            login_log.logout_time = datetime.utcnow()
            if login_log.login_time:
                duration = (login_log.logout_time - login_log.login_time).total_seconds()
                login_log.session_duration = int(duration)
            db.session.commit()
    
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_agents = User.query.filter_by(role='agent').count()
    total_customers = CustomerData.query.count()
    total_uploads = Upload.query.count()
    recent_uploads = Upload.query.order_by(Upload.upload_date.desc()).limit(10).all()
    recent_logins = LoginLog.query.order_by(LoginLog.login_time.desc()).limit(20).all()
    pending_duplicates = DuplicateRecordLog.query.filter_by(action_taken='pending').count()
    
    return render_template('admin_dashboard.html',
                         total_agents=total_agents,
                         total_customers=total_customers,
                         total_uploads=total_uploads,
                         recent_uploads=recent_uploads,
                         recent_logins=recent_logins,
                         pending_duplicates=pending_duplicates)

@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and file.filename.endswith(('.xlsx', '.xls')):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            try:
                df, _ = read_excel_file(file_path)
                detected = detect_columns_by_content(df)
                preview = []
                for _, row in df.head(5).iterrows():
                    preview.append({col: str(row[col]) if not pd.isna(row[col]) else '' for col in df.columns})
                session['pending_file'] = {
                    'file_path': file_path,
                    'filename': filename,
                    'available_columns': list(df.columns),
                    'detected_mapping': detected,
                    'preview_data': preview
                }
                return redirect(url_for('manual_column_mapping'))
            except Exception as e:
                flash(f"Error reading file: {str(e)}", 'danger')
                return redirect(url_for('admin_upload'))
        else:
            flash('Please upload an Excel file (.xlsx or .xls)', 'danger')
            return redirect(request.url)
    
    return render_template('admin_upload.html')

@app.route('/admin/sync', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_sync():
    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if not file.filename.endswith(('.xlsx', '.xls')):
            flash('Please upload an Excel file (.xlsx or .xls)', 'danger')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"sync_{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        try:
            df, _ = read_excel_file(file_path)
            detected = detect_columns_by_content(df)
            preview = []
            for _, row in df.head(5).iterrows():
                preview.append({col: str(row[col]) if not pd.isna(row[col]) else '' for col in df.columns})
            session['pending_file'] = {
                'file_path': file_path,
                'filename': filename,
                'available_columns': list(df.columns),
                'detected_mapping': detected,
                'preview_data': preview,
                'is_sync': True
            }
            return redirect(url_for('manual_column_mapping'))
        except Exception as e:
            flash(f"Error reading file: {str(e)}", 'danger')
            return redirect(url_for('admin_sync'))

    recent_syncs = Upload.query.filter_by(status='synced').order_by(Upload.upload_date.desc()).limit(10).all()
    return render_template('admin_sync.html', recent_syncs=recent_syncs)

@app.route('/admin/manual-mapping', methods=['GET', 'POST'])
@login_required
@admin_required
def manual_column_mapping():
    if 'pending_file' not in session:
        flash('No file pending for mapping', 'danger')
        return redirect(url_for('admin_upload'))
    
    pending = session['pending_file']
    
    if request.method == 'POST':
        manual_mapping = {
            'name': request.form.get('name_column'),
            'contact_number': request.form.get('contact_column'),
            'ic_number': request.form.get('ic_column'),
            'address': request.form.get('address_column'),
            'email': request.form.get('email_column')
        }
        manual_mapping = {k: v for k, v in manual_mapping.items() if v}

        mapped_cols = set(manual_mapping.values())
        all_cols = pending.get('available_columns', [])
        extra_columns = {}
        for col in all_cols:
            if col in mapped_cols:
                continue
            col_key = col.replace(' ', '_').replace('.', '_')
            if request.form.get(f'extra_include_{col_key}'):
                label = request.form.get(f'extra_label_{col_key}', '').strip()
                extra_columns[col] = label if label else col

        is_sync = pending.get('is_sync', False)
        session.pop('pending_file', None)

        if is_sync:
            result = sync_file_with_mapping(pending['file_path'], current_user.id, manual_mapping, extra_columns)
            if result.get('success'):
                flash(f"Sync complete — Updated: {result['updated']}, New: {result['inserted']}, Unchanged: {result['unchanged']}", 'success')
                if result.get('errors'):
                    flash(f"Warnings: {', '.join(result['errors'][:5])}", 'warning')
            else:
                flash(f"Sync failed: {result.get('error', 'Unknown error')}", 'danger')
            return redirect(url_for('admin_dashboard'))

        result = process_uploaded_file_with_mapping(pending['file_path'], current_user.id, manual_mapping, extra_columns)

        if result.get('success'):
            flash(result.get('message', 'File uploaded successfully!'), 'success')
            if result.get('errors'):
                flash(f"Warnings: {', '.join(result['errors'][:5])}", 'warning')
            return redirect(url_for('admin_dashboard'))
        elif result.get('needs_review'):
            flash(f"Found {result['duplicate_count']} duplicate records. Please review and resolve.", 'warning')
            return redirect(url_for('resolve_duplicates', upload_id=result['upload_id']))
        else:
            flash(f"Error processing file: {result.get('error', 'Unknown error')}", 'danger')
            return redirect(url_for('admin_upload'))
    
    detected = pending.get('detected_mapping', {})
    mapped_cols = set(detected.values())
    extra_cols = [col for col in pending['available_columns'] if col not in mapped_cols]
    return render_template('manual_mapping.html',
                         filename=pending['filename'],
                         columns=pending['available_columns'],
                         detected=detected,
                         extra_cols=extra_cols,
                         preview=pending['preview_data'])

@app.route('/admin/duplicates/<int:upload_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def resolve_duplicates(upload_id):
    duplicates = DuplicateRecordLog.query.filter_by(upload_id=upload_id, action_taken='pending').all()
    upload = Upload.query.get_or_404(upload_id)
    
    if request.method == 'POST':
        for dup in duplicates:
            action = request.form.get(f'duplicate_{dup.id}')
            
            if action == 'update':
                new_data = json.loads(dup.duplicate_data)
                customer = CustomerData.query.get(dup.existing_customer_id)
                
                if customer:
                    if 'name' in new_data and new_data['name']:
                        customer.name = new_data['name']
                    if 'contact_number' in new_data and new_data['contact_number']:
                        customer.contact_number = new_data['contact_number']
                    if 'ic_number' in new_data and new_data['ic_number']:
                        customer.ic_number = new_data['ic_number']
                    if 'address' in new_data and new_data['address']:
                        customer.address = new_data['address']
                    if 'email' in new_data and new_data['email']:
                        customer.email = new_data['email']
                    
                    customer.updated_at = datetime.utcnow()
                    dup.action_taken = 'updated'
                    dup.resolution_time = datetime.utcnow()
                    
            elif action == 'merge':
                new_data = json.loads(dup.duplicate_data)
                customer = CustomerData.query.get(dup.existing_customer_id)
                
                if customer:
                    existing_extra = json.loads(customer.additional_data) if customer.additional_data else {}
                    for key, value in new_data.items():
                        if value and value != 'nan' and value != 'None' and value != '':
                            if key not in ['name', 'contact_number', 'ic_number', 'address', 'email']:
                                existing_extra[key] = value
                    customer.additional_data = json.dumps(existing_extra)
                    dup.action_taken = 'merged'
                    dup.resolution_time = datetime.utcnow()
                    
            elif action == 'skip':
                dup.action_taken = 'skipped'
                dup.resolution_time = datetime.utcnow()
        
        db.session.commit()
        upload.status = 'processed'
        db.session.commit()
        
        flash('Duplicates resolved successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    for dup in duplicates:
        dup.customer = CustomerData.query.get(dup.existing_customer_id)
        dup.duplicate_data_parsed = json.loads(dup.duplicate_data)
    
    return render_template('resolve_duplicates.html', duplicates=duplicates, upload=upload)

@app.route('/admin/agents')
@login_required
@admin_required
def admin_agents():
    agents = User.query.filter_by(role='agent').all()
    return render_template('admin_agents.html', agents=agents)

@app.route('/admin/agent/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_agent():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        
        existing = User.query.filter(or_(User.username == username, User.email == email)).first()
        if existing:
            flash('Username or email already exists', 'danger')
            return redirect(request.url)
        
        user = User(
            username=username,
            email=email,
            role='agent',
            full_name=full_name,
            phone=phone,
            is_active=True
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'Agent {full_name} added successfully', 'success')
        return redirect(url_for('admin_agents'))
    
    return render_template('add_agent.html')

@app.route('/admin/agents/bulk-upload', methods=['GET', 'POST'])
@login_required
@admin_required
def bulk_upload_agents():
    if request.method == 'POST':
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if not file.filename.endswith(('.xlsx', '.xls')):
            flash('Please upload an Excel file (.xlsx or .xls)', 'danger')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"agents_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
        file.save(file_path)

        try:
            df = pd.read_excel(file_path, engine='openpyxl')
            df.columns = [str(c).strip().lower().replace(' ', '_') for c in df.columns]

            added = 0
            skipped = 0
            errors = []

            for idx, row in df.iterrows():
                try:
                    username  = clean_data_value(row.get('username', ''))
                    email     = clean_data_value(row.get('email', ''))
                    password  = clean_data_value(row.get('password', ''))
                    full_name = clean_data_value(row.get('full_name', row.get('name', '')))
                    phone     = clean_data_value(row.get('phone', row.get('phone_number', '')))

                    if not username or not email or not password:
                        errors.append(f"Row {idx+2}: Missing username, email or password — skipped")
                        skipped += 1
                        continue

                    if User.query.filter(or_(User.username == username, User.email == email)).first():
                        errors.append(f"Row {idx+2}: {username} / {email} already exists — skipped")
                        skipped += 1
                        continue

                    user = User(username=username, email=email, role='agent',
                                full_name=full_name, phone=phone, is_active=True)
                    user.set_password(password)
                    db.session.add(user)
                    added += 1

                except Exception as e:
                    errors.append(f"Row {idx+2}: {str(e)}")
                    skipped += 1

            db.session.commit()
            flash(f'Bulk upload done — Added: {added}, Skipped: {skipped}', 'success' if added else 'warning')
            if errors:
                flash('Issues: ' + ' | '.join(errors[:5]), 'warning')

        except Exception as e:
            flash(f'Error reading file: {str(e)}', 'danger')

        return redirect(url_for('admin_agents'))

    return render_template('bulk_upload_agents.html')

@app.route('/admin/agent/<int:agent_id>/change-password', methods=['POST'])
@login_required
@admin_required
def change_agent_password(agent_id):
    agent = User.query.get_or_404(agent_id)
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    if not new_password:
        flash('Password cannot be empty', 'danger')
    elif len(new_password) < 6:
        flash('Password must be at least 6 characters', 'danger')
    elif new_password != confirm_password:
        flash('Passwords do not match', 'danger')
    else:
        agent.set_password(new_password)
        db.session.commit()
        flash(f'Password updated for {agent.full_name}', 'success')

    return redirect(url_for('admin_agents'))

@app.route('/admin/agent/<int:agent_id>/toggle')
@login_required
@admin_required
def toggle_agent(agent_id):
    agent = User.query.get_or_404(agent_id)
    agent.is_active = not agent.is_active
    db.session.commit()
    
    status = 'activated' if agent.is_active else 'deactivated'
    flash(f'Agent {agent.username} {status}', 'success')
    return redirect(url_for('admin_agents'))

@app.route('/admin/credits/add', methods=['POST'])
@login_required
@admin_required
def admin_add_credits():
    action = request.form.get('credit_action')
    amount = int(request.form.get('amount', 0))

    if amount <= 0:
        flash('Amount must be greater than 0.', 'danger')
        return redirect(url_for('admin_agents'))

    if action == 'all':
        agents = User.query.filter_by(role='agent').all()
        for agent in agents:
            agent.credit_balance += amount
            db.session.add(CreditLog(
                user_id=agent.id,
                amount=amount,
                balance_after=agent.credit_balance,
                reason=f'Admin bulk top-up',
                admin_id=current_user.id
            ))
        db.session.commit()
        flash(f'Added {amount} credit(s) to all {len(agents)} agents.', 'success')

    elif action == 'specific':
        raw = request.form.get('agent_ids', '')
        ids = [i.strip() for i in raw.replace(',', ' ').split() if i.strip().isdigit()]
        if not ids:
            flash('No valid agent IDs entered.', 'danger')
            return redirect(url_for('admin_agents'))
        count = 0
        for aid in ids:
            agent = User.query.filter_by(id=int(aid), role='agent').first()
            if agent:
                agent.credit_balance += amount
                db.session.add(CreditLog(
                    user_id=agent.id,
                    amount=amount,
                    balance_after=agent.credit_balance,
                    reason=f'Admin top-up',
                    admin_id=current_user.id
                ))
                count += 1
        db.session.commit()
        flash(f'Added {amount} credit(s) to {count} agent(s).', 'success')

    return redirect(url_for('admin_agents'))

@app.route('/admin/search', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_search():
    results = []
    search_term = ''
    search_type = ''

    if request.method == 'POST':
        search_term = request.form.get('search_term', '').strip()
        search_type = request.form.get('search_type', '')

        if search_type == 'name':
            results = CustomerData.query.filter(CustomerData.name.ilike(f'%{search_term}%')).all()
        elif search_type == 'phone':
            results = CustomerData.query.filter(CustomerData.contact_number.ilike(f'%{search_term}%')).all()
        elif search_type == 'ic':
            results = search_by_ic(search_term)

        flash(f'Found {len(results)} result(s)', 'info')

    return render_template('admin_search.html', results=results, search_term=search_term, search_type=search_type)

@app.route('/admin/waiting-approval')
def waiting_approval():
    token = session.get('pending_approval_token')
    if not token:
        return redirect(url_for('login'))
    approval = AdminLoginApproval.query.filter_by(approval_token=token).first()
    if not approval:
        return redirect(url_for('login'))
    return render_template('waiting_approval.html', token=token,
                           expires_at=approval.expires_at.isoformat())

@app.route('/admin/check-approval/<token>')
def check_approval(token):
    approval = AdminLoginApproval.query.filter_by(approval_token=token).first()
    if not approval:
        return jsonify({'status': 'not_found'})

    if approval.status == 'pending' and datetime.utcnow() > approval.expires_at:
        approval.status = 'expired'
        SystemSettings.set('system_locked', '1')
        SystemSettings.set('system_locked_reason',
            f'Admin login approval expired at {datetime.utcnow().strftime("%Y-%m-%d %H:%M")} '
            f'for {approval.user.full_name} from {approval.ip_address}')
        db.session.commit()
        return jsonify({'status': 'expired'})

    if approval.status == 'approved':
        user = User.query.get(approval.user_id)
        if user and user.is_active:
            session_id = str(uuid.uuid4())
            login_log = LoginLog(
                user_id=user.id,
                ip_address=approval.ip_address,
                location=get_location_from_ip(approval.ip_address),
                device_info='Telegram-approved login',
                connection_type='wifi',
                session_id=session_id
            )
            db.session.add(login_log)
            device = AdminDevice.query.filter_by(
                user_id=user.id, fingerprint=approval.fingerprint).first()
            if device:
                device.status = 'trusted'
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            session['login_log_id'] = login_log.id
            session['session_id'] = session_id
            session.pop('pending_approval_token', None)
        return jsonify({'status': 'approved'})

    return jsonify({'status': approval.status})

@app.route('/telegram/webhook', methods=['POST'])
def telegram_webhook():
    data = request.json
    if not data or 'callback_query' not in data:
        return jsonify({'ok': True})

    cb = data['callback_query']
    cb_data = cb.get('data', '')
    cb_id = cb['id']
    msg = cb.get('message', {})
    message_id = msg.get('message_id')
    chat_id = msg.get('chat', {}).get('id')

    if '_' not in cb_data:
        return jsonify({'ok': True})

    action, token = cb_data.split('_', 1)
    approval = AdminLoginApproval.query.filter_by(approval_token=token).first()

    if not approval or approval.status != 'pending':
        tg_answer_callback(cb_id, 'This request has already been handled.')
        return jsonify({'ok': True})

    if datetime.utcnow() > approval.expires_at:
        approval.status = 'expired'
        db.session.commit()
        tg_answer_callback(cb_id, 'This request has expired.')
        tg_edit_message(chat_id, message_id, '⏰ *Login request expired.*')
        return jsonify({'ok': True})

    if action == 'approve':
        approval.status = 'approved'
        db.session.commit()
        tg_answer_callback(cb_id, f'✅ Login approved for {approval.user.full_name}')
        tg_edit_message(chat_id, message_id,
            f'✅ *Login Approved*\n\n'
            f'Admin: *{approval.user.full_name}*\n'
            f'IP: `{approval.ip_address}`\n'
            f'Approved at: {datetime.utcnow().strftime("%Y-%m-%d %H:%M")} UTC')

    elif action == 'decline':
        approval.status = 'declined'
        db.session.commit()
        tg_answer_callback(cb_id, f'❌ Login declined for {approval.user.full_name}')
        tg_edit_message(chat_id, message_id,
            f'❌ *Login Declined*\n\n'
            f'Admin: *{approval.user.full_name}*\n'
            f'IP: `{approval.ip_address}`\n'
            f'Declined at: {datetime.utcnow().strftime("%Y-%m-%d %H:%M")} UTC')

    return jsonify({'ok': True})

@app.route('/admin/unlock-system')
@login_required
@admin_required
def unlock_system():
    SystemSettings.set('system_locked', '0')
    SystemSettings.set('system_locked_reason', '')
    flash('System unlocked. All users can now log in.', 'success')
    return redirect(url_for('admin_security'))

@app.route('/system-locked')
def system_locked_page():
    reason = SystemSettings.get('system_locked_reason', 'Unauthorised login attempt detected.')
    return render_template('system_locked.html', reason=reason), 423

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def force_change_password():
    if request.method == 'POST':
        new_pw = request.form.get('new_password', '').strip()
        confirm_pw = request.form.get('confirm_password', '').strip()
        if len(new_pw) < 6:
            flash('Password must be at least 6 characters.', 'danger')
        elif new_pw != confirm_pw:
            flash('Passwords do not match.', 'danger')
        elif current_user.check_password(new_pw):
            flash('New password cannot be the same as your current password.', 'danger')
        else:
            current_user.set_password(new_pw)
            db.session.commit()
            session.pop('force_pw_change', None)
            flash('Password updated successfully!', 'success')
            return redirect(url_for('admin_dashboard') if current_user.role == 'admin' else url_for('agent_dashboard'))
    return render_template('force_change_password.html')

@app.route('/admin/security', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_security():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'password_policy':
            expiry = request.form.get('password_expiry_days', '0')
            SystemSettings.set('password_expiry_days', expiry)
            if int(expiry) > 0:
                cutoff = datetime.utcnow() - timedelta(days=int(expiry))
                agents = User.query.filter_by(role='agent').all()
                forced = sum(1 for a in agents
                             if not a.password_changed_at or a.password_changed_at < cutoff)
                for a in agents:
                    if not a.password_changed_at or a.password_changed_at < cutoff:
                        a.must_change_password = True
                db.session.commit()
                flash(f'Policy saved — {forced} agent(s) flagged for password reset.', 'success')
            else:
                flash('Password expiry disabled.', 'info')

        elif action == 'telegram_settings':
            SystemSettings.set('telegram_approval_enabled',
                               '1' if request.form.get('telegram_enabled') else '0')
            SystemSettings.set('telegram_bot_token',
                               request.form.get('telegram_bot_token', '').strip())
            SystemSettings.set('telegram_boss_chat_id',
                               request.form.get('telegram_boss_chat_id', '').strip())
            flash('Telegram settings saved.', 'success')

        elif action == 'phase2_toggle':
            SystemSettings.set('phase2_enabled',
                               '1' if request.form.get('phase2_enabled') else '0')
            flash('Phase 2 setting updated.', 'success')

        return redirect(url_for('admin_security'))

    current_expiry = SystemSettings.get('password_expiry_days', '0')
    admin_device_list = AdminDevice.query.order_by(AdminDevice.first_seen.desc()).all()
    system_locked = SystemSettings.get('system_locked', '0') == '1'
    lock_reason = SystemSettings.get('system_locked_reason', '')
    return render_template('admin_security.html',
                           current_expiry=current_expiry,
                           admin_devices=admin_device_list,
                           system_locked=system_locked,
                           lock_reason=lock_reason,
                           telegram_enabled=SystemSettings.get('telegram_approval_enabled', '0'),
                           telegram_bot_token=SystemSettings.get('telegram_bot_token', ''),
                           telegram_boss_chat_id=SystemSettings.get('telegram_boss_chat_id', ''))

@app.route('/admin/phase2')
@login_required
@admin_required
def phase2_overview():
    if SystemSettings.get('phase2_enabled', '0') != '1':
        flash('Phase 2 is not enabled.', 'warning')
        return redirect(url_for('admin_dashboard'))
    return render_template('phase2_overview.html')

@app.route('/admin/admin-device/<int:device_id>/trust')
@login_required
@admin_required
def trust_admin_device(device_id):
    device = AdminDevice.query.get_or_404(device_id)
    device.status = 'trusted'
    db.session.commit()
    flash(f'Device trusted: {device.label}', 'success')
    return redirect(url_for('admin_security'))

@app.route('/admin/admin-device/<int:device_id>/block')
@login_required
@admin_required
def block_admin_device(device_id):
    device = AdminDevice.query.get_or_404(device_id)
    device.status = 'blocked'
    db.session.commit()
    flash(f'Device blocked: {device.label}', 'warning')
    return redirect(url_for('admin_security'))

@app.route('/admin/admin-device/<int:device_id>/delete')
@login_required
@admin_required
def delete_admin_device(device_id):
    device = AdminDevice.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    flash('Device removed.', 'info')
    return redirect(url_for('admin_security'))

@app.route('/admin/devices')
@login_required
@admin_required
def admin_devices():
    pending = AgentDevice.query.filter_by(status='pending').order_by(AgentDevice.first_seen.desc()).all()
    all_devices = AgentDevice.query.order_by(AgentDevice.first_seen.desc()).all()
    return render_template('admin_devices.html', pending=pending, all_devices=all_devices)

@app.route('/admin/device/<int:device_id>/approve')
@login_required
@admin_required
def approve_device(device_id):
    device = AgentDevice.query.get_or_404(device_id)
    device.status = 'approved'
    device.approved_by = current_user.id
    device.approved_at = datetime.utcnow()
    db.session.commit()
    flash(f'Device approved for {device.user.full_name}', 'success')
    return redirect(url_for('admin_devices'))

@app.route('/admin/device/<int:device_id>/block')
@login_required
@admin_required
def block_device(device_id):
    device = AgentDevice.query.get_or_404(device_id)
    device.status = 'blocked'
    db.session.commit()
    flash(f'Device blocked for {device.user.full_name}', 'warning')
    return redirect(url_for('admin_devices'))

@app.route('/admin/device/<int:device_id>/delete')
@login_required
@admin_required
def delete_device(device_id):
    device = AgentDevice.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    flash('Device removed', 'info')
    return redirect(url_for('admin_devices'))

@app.route('/admin/device/<int:device_id>/label', methods=['POST'])
@login_required
@admin_required
def label_device(device_id):
    device = AgentDevice.query.get_or_404(device_id)
    device.label = request.form.get('label', device.label)
    db.session.commit()
    return redirect(url_for('admin_devices'))

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    login_logs = LoginLog.query.order_by(LoginLog.login_time.desc()).limit(100).all()
    search_logs = SearchLog.query.order_by(SearchLog.timestamp.desc()).limit(100).all()
    
    return render_template('admin_logs.html', login_logs=login_logs, search_logs=search_logs)

@app.route('/admin/data/merge', methods=['GET', 'POST'])
@login_required
@admin_required
def merge_data():
    if request.method == 'POST':
        old_upload_id = request.form.get('old_upload_id')
        new_upload_id = request.form.get('new_upload_id')
        
        old_upload = Upload.query.get(old_upload_id)
        new_upload = Upload.query.get(new_upload_id)
        
        if not old_upload or not new_upload:
            flash('Invalid upload selected', 'danger')
            return redirect(request.url)
        
        old_customers = CustomerData.query.filter_by(upload_id=old_upload_id).all()
        new_customers = CustomerData.query.filter_by(upload_id=new_upload_id).all()
        
        updated_count = 0
        new_count = 0
        
        for new_customer in new_customers:
            existing = CustomerData.query.filter(
                or_(
                    CustomerData.ic_number == new_customer.ic_number,
                    CustomerData.contact_number == new_customer.contact_number
                )
            ).first()
            
            if existing:
                if new_customer.name:
                    existing.name = new_customer.name
                if new_customer.contact_number:
                    existing.contact_number = new_customer.contact_number
                if new_customer.address:
                    existing.address = new_customer.address
                if new_customer.email:
                    existing.email = new_customer.email
                existing.updated_at = datetime.utcnow()
                updated_count += 1
            else:
                db.session.add(new_customer)
                new_count += 1
        
        db.session.commit()
        
        flash(f'Data merged successfully! Updated: {updated_count}, New: {new_count}', 'success')
        return redirect(url_for('admin_dashboard'))
    
    uploads = Upload.query.filter_by(status='processed').order_by(Upload.upload_date.desc()).all()
    return render_template('merge_data.html', uploads=uploads)

# ==================== AGENT ROUTES ====================

@app.route('/agent')
@login_required
def agent_dashboard():
    if current_user.role != 'agent':
        return redirect(url_for('admin_dashboard'))
    
    return render_template('agent_dashboard.html')

@app.route('/agent/search', methods=['GET', 'POST'])
@login_required
def agent_search():
    if current_user.role != 'agent':
        return redirect(url_for('admin_dashboard'))

    ip_address = get_client_ip()
    fingerprint = request.form.get('fp') or request.cookies.get('fp', '')

    if fingerprint:
        device_status = check_device_trusted(current_user.id, fingerprint, ip_address)
    else:
        device_status = 'unknown'

    blocked = device_status in ('pending', 'new', 'blocked')

    results = []
    search_term = ''
    search_type = ''

    if request.method == 'POST':
        search_term = request.form.get('search_term', '')
        search_type = request.form.get('search_type', '')

        if not blocked:
            if search_type == 'name':
                results = CustomerData.query.filter(CustomerData.name.like(f'%{search_term}%')).all()
            elif search_type == 'phone':
                results = CustomerData.query.filter(CustomerData.contact_number.like(f'%{search_term}%')).all()
            elif search_type == 'ic':
                results = search_by_ic(search_term)
        
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        
        search_log = SearchLog(
            user_id=current_user.id,
            search_term=search_term,
            search_type=search_type,
            results_count=len(results),
            ip_address=ip_address,
            user_agent=user_agent,
            screenshot_taken=False,
            data_downloaded=False
        )
        db.session.add(search_log)
        db.session.commit()
        
        session['last_search_log_id'] = search_log.id
        
        flash(f'Found {len(results)} results', 'info')
    
    return render_template('agent_search.html', results=results, search_term=search_term,
                           search_type=search_type, blocked=blocked, device_status=device_status)

@app.route('/agent/download/<int:search_log_id>')
@login_required
def download_results(search_log_id):
    if current_user.role != 'agent':
        return redirect(url_for('admin_dashboard'))

    search_log = SearchLog.query.get_or_404(search_log_id)

    if search_log.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('agent_search'))

    if search_log.search_type == 'name':
        results = CustomerData.query.filter(CustomerData.name.like(f'%{search_log.search_term}%')).all()
    elif search_log.search_type == 'phone':
        results = CustomerData.query.filter(CustomerData.contact_number.like(f'%{search_log.search_term}%')).all()
    elif search_log.search_type == 'ic':
        results = search_by_ic(search_log.search_term)
    else:
        results = []

    cost = calc_download_cost(len(results))
    if current_user.credit_balance < cost:
        flash(f'Insufficient credits. This download requires {cost} credit(s) but you only have {current_user.credit_balance}. Please contact your admin.', 'danger')
        return redirect(url_for('agent_search'))

    data = []
    for customer in results:
        additional = json.loads(customer.additional_data) if customer.additional_data else {}
        row = {
            'Name': customer.name,
            'Contact Number': customer.contact_number,
            'IC Number': customer.ic_number,
            'Address': customer.address,
            'Email': customer.email,
        }
        row.update(additional)
        data.append(row)

    df = pd.DataFrame(data)

    filename = f"search_results_{search_log.id}.xlsx"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df.to_excel(filepath, index=False)

    current_user.credit_balance -= cost
    credit_log = CreditLog(
        user_id=current_user.id,
        amount=-cost,
        balance_after=current_user.credit_balance,
        reason=f'Download: {len(results)} row(s) — "{search_log.search_term}"'
    )
    db.session.add(credit_log)
    
    download_log = DataDownloadLog(
        user_id=current_user.id,
        search_log_id=search_log_id,
        download_format='excel',
        ip_address=get_client_ip()
    )
    db.session.add(download_log)
    
    search_log.data_downloaded = True
    db.session.commit()
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/customer/<int:customer_id>/detail')
@login_required
def customer_detail(customer_id):
    customer = CustomerData.query.get_or_404(customer_id)
    additional = json.loads(customer.additional_data) if customer.additional_data else {}
    data = {
        'id': customer.id,
        'name': customer.name,
        'contact_number': customer.contact_number,
        'ic_number': customer.ic_number,
        'address': customer.address,
        'email': customer.email,
        'additional': {k: v for k, v in additional.items() if v and v not in ['', 'nan', 'None']}
    }
    return jsonify(data)

@app.route('/agent/screenshot/<int:search_log_id>', methods=['POST'])
@login_required
def log_screenshot(search_log_id):
    if current_user.role != 'agent':
        return jsonify({'error': 'Unauthorized'}), 403
    
    search_log = SearchLog.query.get_or_404(search_log_id)
    
    if search_log.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    screenshot_log = ScreenshotLog(
        user_id=current_user.id,
        search_log_id=search_log_id,
        screenshot_path=f"screenshot_{search_log_id}_{datetime.now().timestamp()}.png",
        ip_address=get_client_ip()
    )
    db.session.add(screenshot_log)
    
    search_log.screenshot_taken = True
    db.session.commit()
    
    return jsonify({'success': True})

# ==================== HEALTH CHECK ENDPOINT ====================
@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = 'connected'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'environment': 'production' if IS_RENDER else 'development',
        'upload_folder': app.config['UPLOAD_FOLDER']
    }), 200

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

# ==================== INITIALIZATION ====================
def init_database():
    """Initialize database tables and create admin user"""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            app.logger.info("Database tables created successfully")
            print("[INIT] Database tables created successfully")
            
            # Create admin user if not exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    role='admin',
                    full_name='System Administrator',
                    is_active=True
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                app.logger.info("Created admin user")
                print("[INIT] Admin user created: username=admin, password=admin123")
            else:
                app.logger.info("Admin user already exists")
                print("[INIT] Admin user already exists")
                
        except Exception as e:
            app.logger.error(f"Database initialization error: {e}")
            print(f"[INIT ERROR] Database initialization error: {e}")

# Run database initialization
init_database()

# ==================== TELEGRAM POLLING ====================
def telegram_poll_loop():
    """Background thread: poll Telegram getUpdates and process approve/decline callbacks."""
    last_update_id = 0
    while True:
        try:
            with app.app_context():
                bot_token = SystemSettings.get('telegram_bot_token')
                if not bot_token:
                    time.sleep(5)
                    continue
                resp = http_req.get(
                    f'https://api.telegram.org/bot{bot_token}/getUpdates',
                    params={'offset': last_update_id + 1, 'timeout': 20, 'allowed_updates': ['callback_query']},
                    timeout=25
                )
                if not resp.ok:
                    time.sleep(5)
                    continue
                updates = resp.json().get('result', [])
                for update in updates:
                    last_update_id = update['update_id']
                    cb = update.get('callback_query')
                    if not cb:
                        continue
                    cb_data = cb.get('data', '')
                    cb_id = cb['id']
                    if cb_data.startswith('approve_'):
                        token = cb_data[len('approve_'):]
                        approval = AdminLoginApproval.query.filter_by(approval_token=token, status='pending').first()
                        if approval:
                            approval.status = 'approved'
                            db.session.commit()
                            tg_answer_callback(cb_id, '✅ Login approved!')
                            tg_edit_message(cb['message']['chat']['id'],
                                            cb['message']['message_id'],
                                            f"✅ *Login Approved*\nAccess granted for {approval.user.full_name}.")
                            print(f"[TELEGRAM] Approved login for user {approval.user_id}")
                        else:
                            tg_answer_callback(cb_id, 'Request not found or already handled.')
                    elif cb_data.startswith('decline_'):
                        token = cb_data[len('decline_'):]
                        approval = AdminLoginApproval.query.filter_by(approval_token=token, status='pending').first()
                        if approval:
                            approval.status = 'declined'
                            db.session.commit()
                            tg_answer_callback(cb_id, '❌ Login declined.')
                            tg_edit_message(cb['message']['chat']['id'],
                                            cb['message']['message_id'],
                                            f"❌ *Login Declined*\nAccess denied for {approval.user.full_name}.")
                            print(f"[TELEGRAM] Declined login for user {approval.user_id}")
                        else:
                            tg_answer_callback(cb_id, 'Request not found or already handled.')
        except Exception as e:
            print(f"[TELEGRAM POLL] Error: {e}")
            time.sleep(5)

# Start Telegram polling only in production or main process
if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    poll_thread = threading.Thread(target=telegram_poll_loop, daemon=True)
    poll_thread.start()
    print("[TELEGRAM] Polling thread started")

# ==================== MAIN ENTRY POINT ====================
if __name__ == '__main__':
    # Use port from environment variable for Render
    port = int(os.environ.get('PORT', 5000))
    
    # Run with debug=False in production
    if IS_RENDER:
        app.run(host='0.0.0.0', port=port, debug=False)
        print(f"[STARTUP] Running in production mode on port {port}")
    else:
        app.run(debug=True, host='0.0.0.0', port=port)
        print(f"[STARTUP] Running in development mode on port {port}")