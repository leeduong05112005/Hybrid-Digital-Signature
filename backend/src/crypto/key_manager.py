from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from src.crypto import dilithium_impl, ed25519_impl

BASE_DIR = Path(__file__).resolve().parents[2]
LOG_DIR = BASE_DIR / "logs"
KEY_STORE_FILE = LOG_DIR / "key_store.json"
AUDIT_FILE = LOG_DIR / "key_audit.log"

DEFAULT_SIGNING_KEY_ID = "public_key"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ensure_storage():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not KEY_STORE_FILE.exists():
        KEY_STORE_FILE.write_text(json.dumps({"keys": {}, "active_key_id": None}, indent=2), encoding="utf-8")
    if not AUDIT_FILE.exists():
        AUDIT_FILE.write_text("", encoding="utf-8")


def _load_store() -> dict:
    _ensure_storage()
    return json.loads(KEY_STORE_FILE.read_text(encoding="utf-8"))


def _save_store(data: dict):
    KEY_STORE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _append_audit(event: str):
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(f"[{_utc_now()}] {event}\n")


def create_initial_keypair(key_id: str = DEFAULT_SIGNING_KEY_ID, dilithium_algorithm: str = "Dilithium2"):
    """
    Chỉ dùng 1 lần để khởi tạo khóa cho trường.
    Không gọi lại mỗi lần ký.
    """
    store = _load_store()
    if key_id in store["keys"]:
        return

    kp_ed = ed25519_impl.generate_ed25519()
    kp_di = dilithium_impl.generate_dilithium(dilithium_algorithm)

    ed_private_pem = ed25519_impl.export_private_pem(kp_ed.private_key).decode("utf-8")
    ed_public_pem = ed25519_impl.export_public_pem(kp_ed.public_key).decode("utf-8")
    di_private_b64 = kp_di.private_key.hex()
    di_public_b64 = dilithium_impl.export_public_key(kp_di.public_key)

    store["keys"][key_id] = {
        "created_at": _utc_now(),
        "status": "active",
        "ed25519": {
            "private_pem": ed_private_pem,
            "public_pem": ed_public_pem,
        },
        "dilithium": {
            "algorithm": dilithium_algorithm,
            "private_hex": di_private_b64,
            "public_b64": di_public_b64,
        }
    }
    store["active_key_id"] = key_id
    _save_store(store)
    _append_audit(f"Created keypair: {key_id}")


def get_active_key_id() -> str:
    store = _load_store()
    key_id = store.get("active_key_id")
    if not key_id:
        raise RuntimeError("Chưa có active_key_id trong key store")
    return key_id


def get_current_signing_key() -> dict:
    store = _load_store()
    key_id = store.get("active_key_id")
    if not key_id or key_id not in store["keys"]:
        raise RuntimeError("Không tìm thấy khóa ký hiện hành")
    key_data = store["keys"][key_id]
    return {"key_id": key_id, **key_data}


def get_public_keys(key_id: str) -> dict:
    store = _load_store()
    if key_id not in store["keys"]:
        raise KeyError(f"Không tồn tại key_id: {key_id}")
    key_data = store["keys"][key_id]
    return {
        "ed_public_pem": key_data["ed25519"]["public_pem"],
        "di_public_b64": key_data["dilithium"]["public_b64"],
        "di_algorithm": key_data["dilithium"]["algorithm"],
    }


def get_private_keys_for_signing() -> dict:
    current = get_current_signing_key()
    return {
        "key_id": current["key_id"],
        "ed_private_pem": current["ed25519"]["private_pem"],
        "di_private_hex": current["dilithium"]["private_hex"],
        "di_algorithm": current["dilithium"]["algorithm"],
    }