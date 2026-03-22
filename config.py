from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / 'backend'
DATA_DIR = ROOT / 'data'
OUTPUTS_DIR = ROOT / 'outputs'
UPLOADS_DIR = ROOT / 'uploads'
LOGS_DIR = ROOT / 'logs'
CONFIG_DIR = ROOT / 'config'
FRONTEND_DIR = ROOT / 'frontend'
TEMPLATES_DIR = FRONTEND_DIR / 'templates'
STATIC_DIR = FRONTEND_DIR / 'static'
AUTH_DB = DATA_DIR / 'auth.db'
AUDIT_DB = DATA_DIR / 'audit.db'
APP_NAME = 'Hệ thống Chữ ký số Dithium2'
APP_VERSION = '2.0.0'
DEFAULT_HOST = os.getenv('TLU_SIGN_HOST', '127.0.0.1')
DEFAULT_PORT = int(os.getenv('TLU_SIGN_PORT', '5000'))
SECRET_KEY = os.getenv('TLU_SIGN_SECRET_KEY', 'change-this-in-production-tlu-signature-system')
DEBUG = os.getenv('TLU_SIGN_DEBUG', '1') == '1'

for folder in [DATA_DIR, OUTPUTS_DIR, UPLOADS_DIR, LOGS_DIR, CONFIG_DIR, STATIC_DIR / 'assets' / 'slider']:
    folder.mkdir(parents=True, exist_ok=True)
