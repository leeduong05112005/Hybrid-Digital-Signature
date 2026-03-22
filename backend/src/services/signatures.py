from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from src.crypto import key_manager
from src.crypto import dilithium_impl, ed25519_impl
from src.crypto.utils import b64d, b64e, compute_integrity_digest

PHIEN_BAN = "2.0"

def chuan_hoa_json(doi_tuong: dict) -> bytes:
    return json.dumps(doi_tuong, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def tao_thong_tin_ky(du_lieu: bytes, thuat_toan_bam: str, ten_tep_goc: str = "", file_type: str = "") -> dict:
    return {
        "artifact_version": PHIEN_BAN,
        "message_b64": b64e(du_lieu),
        "integrity_digest_hex": compute_integrity_digest(du_lieu, thuat_toan_bam, length=32).hex(),
        "int_hash_algorithm": thuat_toan_bam,
        "payload_size": len(du_lieu),
        "original_filename": ten_tep_goc or "",
        "file_type": file_type or "application/octet-stream",
    }

def lay_khoa_ky() -> dict:
    try:
        return key_manager.lay_private_key_de_ky()
    except Exception:
        key_manager.tao_key_ban_dau()
        return key_manager.lay_private_key_de_ky()

def thuc_hien_ky(du_lieu_da_chuan_hoa: bytes, thong_tin_khoa: dict) -> Tuple[list, int]:
    privateKey_ed = ed25519_impl.pem_to_private_key(thong_tin_khoa["privateKey_ed_pem"].encode("utf-8"))
    signature_ed = ed25519_impl.tao_signature(privateKey_ed, du_lieu_da_chuan_hoa)
    
    privateKey_di = dilithium_impl.hex_to_privateKey(thong_tin_khoa["privateKey_di_hex"])
    signature_di = dilithium_impl.tao_signature(privateKey_di, du_lieu_da_chuan_hoa, thong_tin_khoa["algorithm"])
    
    signature_list = [
        {"alg": "ed25519", "sig": b64e(signature_ed), "kid": thong_tin_khoa["id_khoa"]},
        {"alg": thong_tin_khoa["algorithm"].lower(), "sig": b64e(signature_di), "kid": thong_tin_khoa["id_khoa"]},
    ]
    signature_size = len(signature_ed) + len(signature_di)
    return signature_list, signature_size

@dataclass
class KetQuaKy:
    message_b64: str
    ma_bam_toan_ven: str
    signatures: list
    signature_size: int
    thoi_gian_ky_ms: float = 0.0
    phien_ban: str = PHIEN_BAN
    thuat_toan_bam: str = "shake256"
    dulieu_size: int = 0
    ten_tep_goc: str = ""
    file_type: str = "application/octet-stream"
    
    def to_dict(self) -> dict:
        return {
            "artifact_version": self.phien_ban,
            "message_b64": self.message_b64,
            "integrity_digest_hex": self.ma_bam_toan_ven,
            "int_hash_algorithm": self.thuat_toan_bam,
            "payload_size": self.dulieu_size,
            "original_filename": self.ten_tep_goc,
            "file_type": self.file_type,
            "signatures": self.signatures,
            "signature_size": self.signature_size,
            "sign_time_ms": self.thoi_gian_ky_ms,
        }

def ky_dulieu(du_lieu: bytes, thuat_toan_bam: str, ten_tep_goc: str = "", file_type: str = "") -> KetQuaKy:
    time_start = time.time()
    khoa_ky = lay_khoa_ky()
    thong_tin = tao_thong_tin_ky(du_lieu, thuat_toan_bam, ten_tep_goc, file_type)
    signature_moi, kich_thuoc = thuc_hien_ky(chuan_hoa_json(thong_tin), khoa_ky)
    
    # SỬA LỖI: signature -> signatures để khớp với Dataclass
    return KetQuaKy(
        message_b64=thong_tin["message_b64"],
        ma_bam_toan_ven=thong_tin["integrity_digest_hex"],
        signatures=signature_moi,
        signature_size=kich_thuoc,
        thoi_gian_ky_ms=round((time.time() - time_start) * 1000, 2),
        thuat_toan_bam=thong_tin["int_hash_algorithm"],
        dulieu_size=thong_tin["payload_size"],
        ten_tep_goc=thong_tin["original_filename"],
        file_type=thong_tin["file_type"],
    )

def them_signature(du_lieu_signature: bytes) -> dict:
    time_start = time.time()
    try:
        dulieu_json = json.loads(du_lieu_signature.decode("utf-8"))
    except Exception:
        raise ValueError("File chữ ký bị lỗi cấu trúc, không đọc được.")
    khoa_ky = lay_khoa_ky()
    thong_tin = {
        "artifact_version": dulieu_json.get("artifact_version", PHIEN_BAN),
        "message_b64": dulieu_json["message_b64"],
        "integrity_digest_hex": dulieu_json["integrity_digest_hex"],
        "int_hash_algorithm": dulieu_json.get("int_hash_algorithm", "shake256"),
        "payload_size": dulieu_json.get("payload_size", len(b64d(dulieu_json["message_b64"]))),
        "original_filename": dulieu_json.get("original_filename", ""),
        "file_type": dulieu_json.get("file_type", "application/octet-stream"),
    }
    signature_moi, kich_thuoc_moi = thuc_hien_ky(chuan_hoa_json(thong_tin), khoa_ky)
    thoi_gian_xu_ly_ms = round((time.time() - time_start) * 1000, 2)
    
    dulieu_json.setdefault("signatures", []).extend(signature_moi)
    dulieu_json["signature_size"] = dulieu_json.get("signature_size", 0) + kich_thuoc_moi
    dulieu_json["sign_time_ms"] = round(dulieu_json.get("sign_time_ms", 0.0) + thoi_gian_xu_ly_ms, 2)
    dulieu_json.update(thong_tin)
    return dulieu_json

def xac_thuc_signature(du_lieu_signature: bytes, du_lieu_goc: bytes, danh_sach_khoa_ngoai: list | None = None) -> Tuple[bool, dict]:
    time_start = time.time()
    try:
        dulieu_json = json.loads(du_lieu_signature.decode("utf-8"))
    except Exception:
        return False, {"Lí do": "File chữ ký không phải JSON hợp lệ"}
        
    if b64d(dulieu_json.get("message_b64", "")) != du_lieu_goc:
        return False, {"Lí do": "Nội dung file hiện tại khác với lúc được ký"}
    if dulieu_json.get("payload_size") not in (None, len(du_lieu_goc)):
        return False, {"Lí do": "Kích thước của tài liệu đã bị thay đổi"}
        
    thuat_toan_bam = dulieu_json.get("int_hash_algorithm", "shake256")
    if compute_integrity_digest(du_lieu_goc, thuat_toan_bam, length=32).hex() != dulieu_json.get("integrity_digest_hex"):
        return False, {"Lí do": "Dữ liệu đã bị can thiệp (Mã kiểm tra không khớp)"}
        
    thong_tin = {
        "artifact_version": dulieu_json.get("artifact_version", PHIEN_BAN),
        "message_b64": dulieu_json.get("message_b64", ""),
        "integrity_digest_hex": dulieu_json.get("integrity_digest_hex", ""),
        "int_hash_algorithm": thuat_toan_bam,
        "payload_size": dulieu_json.get("payload_size", len(du_lieu_goc)),
        "original_filename": dulieu_json.get("original_filename", ""),
        "file_type": dulieu_json.get("file_type", "application/octet-stream"),
    }
    du_lieu_da_chuan_hoa = chuan_hoa_json(thong_tin)
    danh_sach_ket_qua = []
    
    for signature in dulieu_json.get("signatures", []):
        thuat_toan, id_khoa, hop_le = signature.get("alg"), signature.get("kid"), False
        reason = ""
        try:
            signature_bytes = b64d(signature.get("sig", ""))
            thong_tin_publicKey = next((k for k in (danh_sach_khoa_ngoai or []) if k.get("key_id") == id_khoa), None)
            if not thong_tin_publicKey:
                thong_tin_publicKey = key_manager.lay_public_key(id_khoa)
            
            if not thong_tin_publicKey:
                reason = "Không tìm thấy Chìa khóa công khai của người ký"
            elif thuat_toan == "ed25519":
                publicKey = ed25519_impl.pem_to_public_key(thong_tin_publicKey["publicKey_ed_pem"].encode("utf-8"))
                hop_le = ed25519_impl.check_signature(publicKey, du_lieu_da_chuan_hoa, signature_bytes)
            elif "dilithium" in thuat_toan.lower():
                publicKey = dilithium_impl.base64_to_publicKey(thong_tin_publicKey["publicKey_di_b64"])
                hop_le = dilithium_impl.check_signature(publicKey, du_lieu_da_chuan_hoa, signature_bytes, thong_tin_publicKey["algorithm"])
        except Exception as e:
            reason = f"Quá trình kiểm tra bị lỗi: {e}"
            
        danh_sach_ket_qua.append({"alg": thuat_toan, "valid": hop_le, "key_id": id_khoa, "reason": reason if not hop_le else "Chữ ký hợp lệ"})
        
    ket_qua_tong = all(r["valid"] for r in danh_sach_ket_qua) if danh_sach_ket_qua else False
    return ket_qua_tong, {
        "details": danh_sach_ket_qua,
        "verification_time_ms": round((time.time() - time_start) * 1000, 2),
        "signature_size": dulieu_json.get("signature_size", 0),
    }

def luu_signature(ket_qua: KetQuaKy, thu_muc: Path, ten_goc: str) -> Path:
    thu_muc.mkdir(parents=True, exist_ok=True)
    duong_dan = thu_muc / f"{ten_goc}.sig.json"
    duong_dan.write_text(json.dumps(ket_qua.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return duong_dan