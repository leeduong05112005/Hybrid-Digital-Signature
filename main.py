from __future__ import annotations

import sys

from config import BACKEND_DIR, APP_NAME, APP_VERSION, DEFAULT_HOST, DEFAULT_PORT, DEBUG

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from backend.src.server.app import app  # noqa: E402

if __name__ == '__main__':
    print(f'{APP_NAME} v{APP_VERSION} đang khởi động (Chế độ Guest)...')
    print(f'Truy cập: http://{DEFAULT_HOST}:{DEFAULT_PORT}')
    # Cập nhật lại danh sách thuật toán hiển thị tại console
    print('Thuật toán hỗ trợ: Ed25519 / Dilithium2')
    
    # Chạy ứng dụng Flask
    app.run(debug=DEBUG, host=DEFAULT_HOST, port=DEFAULT_PORT)