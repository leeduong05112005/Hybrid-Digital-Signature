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

def _chuan_hoa_json(doi_tuong: dict) -> bytes:
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
        return key_manager.lay_khoa_bi_mat_de_ky()
    except Exception:
        key_manager.tao_cap_khoa_ban_dau()
        return key_manager.lay_khoa_bi_mat_de_ky()
def _thuc_hien_ky(du_lieu_da_chuan_hoa: bytes, thong_tin_khoa: dict) -> Tuple[list, int]:
    khoa_bi_mat_ed = ed25519_impl.doc_khoa_bi_mat_tu_chu(thong_tin_khoa["khoa_bi_mat_ed_chu"].encode("utf-8"))
    chu_ky_ed = ed25519_impl.tao_chu_ky(khoa_bi_mat_ed, du_lieu_da_chuan_hoa)
    khoa_bi_mat_di = bytes.fromhex(thong_tin_khoa["khoa_bi_mat_di_hex"])
    chu_ky_di = dilithium_impl.tao_chu_ky(khoa_bi_mat_di, du_lieu_da_chuan_hoa, thong_tin_khoa["thuat_toan_di"])
    danh_sach_chu_ky = [
        {"alg": "ed25519", "sig": b64e(chu_ky_ed), "kid": thong_tin_khoa["id_khoa"]},
        {"alg": "dilithium2", "sig": b64e(chu_ky_di), "kid": thong_tin_khoa["id_khoa"]},
    ]
    tong_kich_thuoc_chu_ky = len(chu_ky_ed) + len(chu_ky_di)
    return danh_sach_chu_ky, tong_kich_thuoc_chu_ky

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
        raise ValueError("File chữ ký bị lỗi cấu trúc, không đọc được.")
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

def xac_thuc_chu_ky(du_lieu_chu_ky: bytes, du_lieu_goc: bytes, danh_sach_khoa_ngoai: list | None = None) -> Tuple[bool, dict]:
    thoi_gian_bat_dau = time.time()
    try:
        du_lieu_json = json.loads(du_lieu_chu_ky.decode("utf-8"))
    except Exception:
        return False, {"Lí do": "File chữ ký không phải JSON hợp lệ"}
    if b64d(du_lieu_json.get("message_b64", "")) != du_lieu_goc:
        return False, {"Lí do": "Nội dung file hiện tại khác với lúc được ký"}
    if du_lieu_json.get("payload_size") not in (None, len(du_lieu_goc)):
        return False, {"Lí do": "Kích thước của tài liệu đã bị thay đổi"}
    thuat_toan_bam = du_lieu_json.get("integrity_hash_algorithm", "shake256")
    if compute_integrity_digest(du_lieu_goc, thuat_toan_bam, length=32).hex() != du_lieu_json.get("integrity_digest_hex"):
        return False, {"Lí do": "Dữ liệu đã bị can thiệp (Mã kiểm tra không khớp)"}
    thong_tin = {
        "artifact_version": du_lieu_json.get("artifact_version", PHIEN_BAN),
        "message_b64": du_lieu_json.get("message_b64", ""),
        "integrity_digest_hex": du_lieu_json.get("integrity_digest_hex", ""),
        "integrity_hash_algorithm": thuat_toan_bam,
        "payload_size": du_lieu_json.get("payload_size", len(du_lieu_goc)),
        "original_filename": du_lieu_json.get("original_filename", ""),
        "file_type": du_lieu_json.get("file_type", "application/octet-stream"),
    }
    du_lieu_da_chuan_hoa = _chuan_hoa_json(thong_tin)
    danh_sach_ket_qua = []
    for chu_ky in du_lieu_json.get("signatures", []):
        thuat_toan, id_khoa, hop_le = chu_ky.get("alg"), chu_ky.get("kid"), False
        ly_do = ""
        try:
            chu_ky_bytes = b64d(chu_ky.get("sig", ""))
            
            thong_tin_khoa_cong_khai = next((k for k in (danh_sach_khoa_ngoai or []) if k.get("key_id") == id_khoa), None)
            if not thong_tin_khoa_cong_khai:
                thong_tin_khoa_cong_khai = key_manager.lay_khoa_cong_khai(id_khoa)
            
            if not thong_tin_khoa_cong_khai:
                ly_do = "Không tìm thấy Chìa khóa công khai của người ký"
            elif thuat_toan == "ed25519":
                khoa_cong_khai = ed25519_impl.doc_khoa_cong_khai_tu_chu(thong_tin_khoa_cong_khai["khoa_cong_khai_ed_chu"].encode("utf-8"))
                hop_le = ed25519_impl.kiem_tra_chu_ky(khoa_cong_khai, du_lieu_da_chuan_hoa, chu_ky_bytes)
            elif thuat_toan == "dilithium2":
                khoa_cong_khai = dilithium_impl.doc_khoa_cong_khai_tu_chu(thong_tin_khoa_cong_khai["khoa_cong_khai_di_b64"])
                hop_le = dilithium_impl.kiem_tra_chu_ky(khoa_cong_khai, du_lieu_da_chuan_hoa, chu_ky_bytes, thong_tin_khoa_cong_khai["thuat_toan_di"])
        except Exception:
            ly_do = "Quá trình kiểm tra bị lỗi (Có thể chữ ký bị sai cấu trúc)"
        danh_sach_ket_qua.append({"alg": thuat_toan, "valid": hop_le, "key_id": id_khoa, "reason": ly_do if not hop_le else "Chữ ký hợp lệ"})
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