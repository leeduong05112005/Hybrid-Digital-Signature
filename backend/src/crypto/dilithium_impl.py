from __future__ import annotations
import base64
from dataclasses import dataclass

try:
    import oqs
    # Test if OQS actually works (not just importable)
    try:
        with oqs.Signature("Dilithium2") as test_sig:
            pass
        OQS_AVAILABLE = True
        OQS_ERROR = ""
    except Exception as e:
        oqs = None
        OQS_AVAILABLE = False
        OQS_ERROR = f"liboqs native library not available: {e}"
except Exception as e:
    oqs = None
    OQS_AVAILABLE = False
    OQS_ERROR = f"liboqs-python not installed or import failed: {e}"


@dataclass
class DilithiumKeyPair:
    private_key: bytes
    public_key: bytes
    algorithm: str = 'Dilithium2'


def is_available() -> bool:
    return oqs is not None and hasattr(oqs, 'Signature')


def requirement_message() -> str:
    return 'Dilithium cần liboqs-python và thư viện native liboqs. Cài bằng: pip install liboqs-python'


def generate_dilithium(algorithm: str = 'Dilithium2') -> DilithiumKeyPair:
    if not is_available():
        raise RuntimeError(requirement_message())
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return DilithiumKeyPair(private_key=secret_key, public_key=public_key, algorithm=algorithm)


def sign(private_key: bytes, message: bytes, algorithm: str = 'Dilithium2') -> bytes:
    if not is_available():
        raise RuntimeError(requirement_message())
    with oqs.Signature(algorithm, secret_key=private_key) as signer:
        return signer.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes, algorithm: str = 'Dilithium2') -> bool:
    if not is_available():
        raise RuntimeError(requirement_message())
    with oqs.Signature(algorithm) as verifier:
        return bool(verifier.verify(message, signature, public_key))


def export_public_key(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode('ascii')


def load_public_key(public_key_b64: str) -> bytes:
    return base64.b64decode(public_key_b64.encode('ascii'))

def ensure_oqs():
    if not OQS_AVAILABLE:
        raise RuntimeError(f"Dilithium chưa sẵn sàng: {OQS_ERROR}")
# thêm mới
def export_private_key_hex(private_key: bytes) -> str:
    return private_key.hex()


def load_private_key_hex(private_key_hex: str) -> bytes:
    return bytes.fromhex(private_key_hex)