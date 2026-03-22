from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / 'backend'
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.crypto import dilithium_impl

print('OQS available:', dilithium_impl.is_available())
if not dilithium_impl.is_available():
    print('❌ Lỗi:', dilithium_impl.OQS_ERROR)
    print(dilithium_impl.requirement_message())
    print("\n=== GIẢI PHÁP FOR WINDOWS ===")
    print("1. Cài conda: https://www.conda.io/projects/conda/en/latest/user-guide/install/windows.html")
    print("2. Tạo env mới: conda create -n tlu python=3.11")
    print("3. Activate: conda activate tlu")
    print("4. Cài từ conda-forge: conda install -c conda-forge liboqs-python")
    print("\nHOẶC chạy mà KHÔNG Dilithium (hệ thống vẫn dùng RSA/ECDSA/Ed25519 được)")
    raise SystemExit(1)

try:
    msg = b'Thang Long University - Dilithium2 self-test'
    kp = dilithium_impl.generate_dilithium('Dilithium2')
    sig = dilithium_impl.sign(kp.private_key, msg, 'Dilithium2')
    ok = dilithium_impl.verify(kp.public_key, msg, sig, 'Dilithium2')
    print('\n✅ Dilithium2 hoạt động tốt!')
    print('Algorithm:', kp.algorithm)
    print('Public key bytes:', len(kp.public_key))
    print('Signature bytes:', len(sig))
    print('Verify:', ok)
except Exception as e:
    print(f"❌ Lỗi khi test Dilithium: {e}")
    raise SystemExit(1)
