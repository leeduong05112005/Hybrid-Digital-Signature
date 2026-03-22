from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict
from src.crypto import ed25519_impl, dilithium_impl

BASE_DIR = Path(__file__).resolve().parents[2]
KEY_DIR = BASE_DIR / "keys"
KEY_FILE = KEY_DIR / "key_store.json"

DEFAULT_KEY_ID = "default_key"

def now():
    return datetime.now(timezone.utc).isoformat()

def ensure_storage():
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if not KEY_FILE.exists():
        KEY_FILE.write_text(json.dumps({
            "current_key_id": None,
            "keys": {}
        }, indent=2), encoding="utf-8")

def read_store():
    ensure_storage()
    return json.loads(KEY_FILE.read_text(encoding="utf-8"))

def write_store(data):
    KEY_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def tao_key_ban_dau(key_id: str = DEFAULT_KEY_ID):
    data = read_store()
    if key_id in data["keys"]:
        return
    ed_keys = ed25519_impl.tao_ed25519()
    private_ed_pem = ed25519_impl.privateKey_to_pem(ed_keys.privateKey).decode()
    public_ed_pem = ed25519_impl.publicKey_to_pem(ed_keys.publicKey).decode()
    dilithium_data = None
    try:
        di_keys = dilithium_impl.tao_dilithium_keys("Dilithium2")
        dilithium_data = {
            "algorithm": "Dilithium2",
            "privateKey_hex": dilithium_impl.privateKey_to_hex(di_keys.privateKey),
            "publicKey_b64": dilithium_impl.publicKey_to_base64(di_keys.publicKey)
        }
    except Exception as e:
        print("[WARN] Dilithium không khả dụng:", e)
    data["keys"][key_id] = {
        "created_at": now(),
        "ed25519": {
            "private": private_ed_pem,
            "public": public_ed_pem
        },
        "dilithium": dilithium_data
    }
    data["current_key_id"] = key_id
    write_store(data)

def get_current_key_id() -> str:
    data = read_store()
    key_id = data.get("current_key_id")
    if not key_id:
        raise RuntimeError("Chưa có key nào được chọn")
    return key_id

def lay_private_key_de_ky() -> Dict:
    data = read_store()
    key_id = get_current_key_id()
    key = data["keys"][key_id]
    result = {
        "id_khoa": key_id,
        "privateKey_ed_pem": key["ed25519"]["private"],
    }
    if key.get("dilithium"):
        result.update({
            "privateKey_di_hex": key["dilithium"]["privateKey_hex"],
            "algorithm": key["dilithium"]["algorithm"]
        })
    return result

def lay_public_key(key_id: str) -> Dict:
    data = read_store()
    if key_id not in data["keys"]:
        raise KeyError("Không tìm thấy key")
    key = data["keys"][key_id]
    result = {
        "publicKey_ed_pem": key["ed25519"]["public"]
    }
    if key.get("dilithium"):
        result.update({
            "publicKey_di_b64": key["dilithium"]["publicKey_b64"],
            "algorithm": key["dilithium"]["algorithm"]
        })

    return result

def init():
    try:
        get_current_key_id()
    except:
        tao_key_ban_dau()

