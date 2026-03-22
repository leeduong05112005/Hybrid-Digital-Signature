from __future__ import annotations
import base64
from dataclasses import dataclass

try:
    import oqs
    try:
        with oqs.Signature("Dilithium2") as test_sig:
            pass
        is_library_available = True
        library_error = ""
    except Exception as e:
        oqs = None
        is_library_available = False
        library_error = f"Thư viện lõi liboqs không khả dụng: {e}"
except Exception as e:
    oqs = None
    is_library_available = False
    library_error = f"Chưa cài liboqs-python hoặc bị lỗi: {e}"

@dataclass
class dilithium:
    privateKey: bytes
    publicKey: bytes
    algorithm: str = 'Dilithium2'

def check_library() -> bool:
    return oqs is not None and hasattr(oqs, 'Signature')

def check_install() -> str:
    return 'Thuật toán Dilithium cần liboqs-python và thư viện nền liboqs. Hãy cài đặt bằng lệnh: pip install liboqs-python'

def tao_dilithium_keys(algorithm: str = 'Dilithium2') -> dilithium:
    if oqs is None:  
        raise RuntimeError(check_install())
        
    with oqs.Signature(algorithm) as signer_tool:
        publicKey = signer_tool.generate_keypair()
        privateKey = signer_tool.export_secret_key()
        
    return dilithium(
        privateKey=privateKey, 
        publicKey=publicKey, 
        algorithm=algorithm
    )

def tao_signature(privateKey: bytes, dulieu_can_ky: bytes, algorithm: str = 'Dilithium2') -> bytes:
    if oqs is None:
        raise RuntimeError(check_install())
        
    with oqs.Signature(algorithm, secret_key=privateKey) as signer_tool:
        return signer_tool.sign(dulieu_can_ky)

def check_signature(publicKey: bytes, dulieu_goc: bytes, signature: bytes, algorithm: str = 'Dilithium2') -> bool:
    if oqs is None: 
        raise RuntimeError(check_install())
        
    with oqs.Signature(algorithm) as signer_tool:
        return bool(signer_tool.verify(dulieu_goc, signature, publicKey))

def publicKey_to_base64(publicKey: bytes) -> str:
    return base64.b64encode(publicKey).decode('ascii')

def base64_to_publicKey(chu_chua_khoa: str) -> bytes:
    return base64.b64decode(chu_chua_khoa.encode('ascii'))

def check_library_status():
    if not check_library():
        raise RuntimeError(f"Thuật toán Dilithium chưa sẵn sàng: {library_error}")
    
def privateKey_to_hex(privateKey: bytes) -> str:
    return privateKey.hex()

def hex_to_privateKey(chu_chua_khoa_hex: str) -> bytes:
    return bytes.fromhex(chu_chua_khoa_hex)