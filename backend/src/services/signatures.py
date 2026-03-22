from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from src.crypto import key_manager
from src.crypto import dilithium_impl, ed25519_impl
from src.crypto.utils import b64d, b64e, compute_integrity_digest

PHIEN_BAN = "3.0"

def _chuan_hoa_json(doi_tuong: dict) -> bytes:
    """Chuẩn hóa JSON để dữ liệu ký luôn ổn định."""
    return json.dumps(doi_tuong, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _tao_thong_tin_ky(du_lieu: bytes, thuat_toan_bam: str, ten_tep_goc: str = "", loai_tep: str = "") -> dict:
    return {
        "artifact_version": PHIEN_BAN,
        "message_b64": b64e(du_lieu),
        "integrity_digest_hex": compute_integrity_digest(du_lieu, thuat_toan_bam, length=32).hex(),
        "integrity_hash_algorithm": thuat_toan_bam,
        "payload_size": len(du_lieu),
        "original_filename": ten_tep_goc or "",
        "file_type": loai_tep or "application/octet-stream",
    }

def _lay_khoa_ky() -> dict:
    try:
        return key_manager.get_private_keys_for_signing()
    except Exception:
        key_manager.create_initial_keypair()
        return key_manager.get_private_keys_for_signing()

def _thuc_hien_ky(du_lieu_da_ky: bytes, khoa_ky: dict) -> Tuple[list, int]:
    ed_private = ed25519_impl.load_private_pem(khoa_ky["ed_private_pem"].encode("utf-8"))
    sig_ed = ed25519_impl.sign(ed_private, du_lieu_da_ky)

    di_private = bytes.fromhex(khoa_ky["di_private_hex"])
    sig_di = dilithium_impl.sign(di_private, du_lieu_da_ky, khoa_ky["di_algorithm"])

    chu_ky = [
        {"alg": "ed25519", "sig": b64e(sig_ed), "kid": khoa_ky["key_id"]},
        {"alg": "dilithium2", "sig": b64e(sig_di), "kid": khoa_ky["key_id"]},
    ]
    return chu_ky, len(sig_ed) + len(sig_di)


@dataclass
class KetQuaKy:
    message_b64: str
    ma_bam_toan_ven: str
    chu_ky: list
    kich_thuoc_chu_ky: int
    thoi_gian_ky_ms: float = 0.0
    phien_ban: str = PHIEN_BAN
    thuat_toan_bam: str = "shake256"
    kich_thuoc_du_lieu: int = 0
    ten_tep_goc: str = ""
    loai_tep: str = "application/octet-stream"

    def to_dict(self) -> dict:
        return {
            "artifact_version": self.phien_ban,
            "message_b64": self.message_b64,
            "integrity_digest_hex": self.ma_bam_toan_ven,
            "integrity_hash_algorithm": self.thuat_toan_bam,
            "payload_size": self.kich_thuoc_du_lieu,
            "original_filename": self.ten_tep_goc,
            "file_type": self.loai_tep,
            "signatures": self.chu_ky,
            "signature_size": self.kich_thuoc_chu_ky,
            "sign_time_ms": self.thoi_gian_ky_ms,
        }

def ky_du_lieu(du_lieu: bytes, thuat_toan_bam: str, ten_tep_goc: str = "", loai_tep: str = "") -> KetQuaKy:
    thoi_gian_bat_dau = time.time()
    khoa_ky = _lay_khoa_ky()
    
    thong_tin = _tao_thong_tin_ky(du_lieu, thuat_toan_bam, ten_tep_goc, loai_tep)
    chu_ky_moi, kich_thuoc = _thuc_hien_ky(_chuan_hoa_json(thong_tin), khoa_ky)

    return KetQuaKy(
        message_b64=thong_tin["message_b64"],
        ma_bam_toan_ven=thong_tin["integrity_digest_hex"],
        chu_ky=chu_ky_moi,
        kich_thuoc_chu_ky=kich_thuoc,
        thoi_gian_ky_ms=round((time.time() - thoi_gian_bat_dau) * 1000, 2),
        thuat_toan_bam=thong_tin["integrity_hash_algorithm"],
        kich_thuoc_du_lieu=thong_tin["payload_size"],
        ten_tep_goc=thong_tin["original_filename"],
        loai_tep=thong_tin["file_type"],
    )


def them_chu_ky(du_lieu_chu_ky: bytes) -> dict:
    thoi_gian_bat_dau = time.time()

    try:
        du_lieu_json = json.loads(du_lieu_chu_ky.decode("utf-8"))
    except Exception:
        raise ValueError("File chữ ký không phải JSON hợp lệ")

    khoa_ky = _lay_khoa_ky()

    thong_tin = {
        "artifact_version": du_lieu_json.get("artifact_version", PHIEN_BAN),
        "message_b64": du_lieu_json["message_b64"],
        "integrity_digest_hex": du_lieu_json["integrity_digest_hex"],
        "integrity_hash_algorithm": du_lieu_json.get("integrity_hash_algorithm", "shake256"),
        "payload_size": du_lieu_json.get("payload_size", len(b64d(du_lieu_json["message_b64"]))),
        "original_filename": du_lieu_json.get("original_filename", ""),
        "file_type": du_lieu_json.get("file_type", "application/octet-stream"),
    }
    
    chu_ky_moi, kich_thuoc_moi = _thuc_hien_ky(_chuan_hoa_json(thong_tin), khoa_ky)
    thoi_gian_xu_ly_ms = round((time.time() - thoi_gian_bat_dau) * 1000, 2)

    du_lieu_json.setdefault("signatures", []).extend(chu_ky_moi)
    du_lieu_json["signature_size"] = du_lieu_json.get("signature_size", 0) + kich_thuoc_moi
    du_lieu_json["sign_time_ms"] = round(du_lieu_json.get("sign_time_ms", 0.0) + thoi_gian_xu_ly_ms, 2)
    du_lieu_json.update(thong_tin)

    return du_lieu_json


def xac_thuc_chu_ky(du_lieu_chu_ky: bytes, du_lieu_goc: bytes, danh_sach_khoa_ngoai: list = None) -> Tuple[bool, dict]:
    thoi_gian_bat_dau = time.time()

    try:
        du_lieu_json = json.loads(du_lieu_chu_ky.decode("utf-8"))
    except Exception:
        return False, {"Lí do": "File chữ ký không phải JSON hợp lệ"}

    if b64d(du_lieu_json.get("message_b64", "")) != du_lieu_goc:
        return False, {"Lí do": "Nội dung không khớp hoàn toàn với dữ liệu đã được ký"}

    if du_lieu_json.get("payload_size") not in (None, len(du_lieu_goc)):
        return False, {"Lí do": "Kích thước dữ liệu đã thay đổi"}

    thuat_toan_bam = du_lieu_json.get("integrity_hash_algorithm", "shake256")
    if compute_integrity_digest(du_lieu_goc, thuat_toan_bam, length=32).hex() != du_lieu_json.get("integrity_digest_hex"):
        return False, {"Lí do": "Mã băm không khớp (Dữ liệu bị sửa đổi)"}

    thong_tin = {
        "artifact_version": du_lieu_json.get("artifact_version", PHIEN_BAN),
        "message_b64": du_lieu_json.get("message_b64", ""),
        "integrity_digest_hex": du_lieu_json.get("integrity_digest_hex", ""),
        "integrity_hash_algorithm": thuat_toan_bam,
        "payload_size": du_lieu_json.get("payload_size", len(du_lieu_goc)),
        "original_filename": du_lieu_json.get("original_filename", ""),
        "file_type": du_lieu_json.get("file_type", "application/octet-stream"),
    }
    du_lieu_da_ky = _chuan_hoa_json(thong_tin)
    danh_sach_ket_qua = []

    for ck in du_lieu_json.get("signatures", []):
        alg, kid, hop_le = ck.get("alg"), ck.get("kid"), False
        ly_do = ""

        try:
            sig_bytes = b64d(ck.get("sig", ""))
            pub = next((k for k in (danh_sach_khoa_ngoai or []) if k.get("key_id") == kid), None)
            if not pub:
                pub = key_manager.get_public_keys(kid)
            
            if not pub:
                ly_do = "Không tìm thấy Public Key tương ứng"
            elif alg == "ed25519":
                hop_le = ed25519_impl.verify(ed25519_impl.load_public_pem(pub["ed_public_pem"].encode("utf-8")), du_lieu_da_ky, sig_bytes)
            elif alg == "dilithium2":
                hop_le = dilithium_impl.verify(dilithium_impl.load_public_key(pub["di_public_b64"]), du_lieu_da_ky, sig_bytes, pub["di_algorithm"])
        except Exception:
            ly_do = "Lỗi trong quá trình xác thực (có thể do chữ ký sai định dạng)"

        danh_sach_ket_qua.append({"alg": alg, "valid": hop_le, "key_id": kid, "reason": ly_do if not hop_le else "Hợp lệ"})

    ket_qua_tong = all(r["valid"] for r in danh_sach_ket_qua) if danh_sach_ket_qua else False

    return ket_qua_tong, {
        "details": danh_sach_ket_qua,
        "verification_time_ms": round((time.time() - thoi_gian_bat_dau) * 1000, 2),
        "signature_size": du_lieu_json.get("signature_size", 0),
    }


def luu_chu_ky(ket_qua: KetQuaKy, thu_muc: Path, ten_goc: str) -> Path:
    thu_muc.mkdir(parents=True, exist_ok=True)
    duong_dan = thu_muc / f"{ten_goc}.sig.json"
    duong_dan.write_text(json.dumps(ket_qua.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return duong_dan