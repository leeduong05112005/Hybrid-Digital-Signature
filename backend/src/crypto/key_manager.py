from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from src.crypto import dilithium_impl, ed25519_impl

THUMUC_GOC = Path(__file__).resolve().parents[2]
THUMUC_NHATKY = THUMUC_GOC / "logs"
TEP_LUU_KHOA = THUMUC_NHATKY / "key_store.json"
TEP_NHATKY_HOAT_DONG = THUMUC_NHATKY / "key_audit.log"

ID_KHOA_MAC_DINH = "public_key"


def _lay_gio_hien_tai_utc() -> str:
    """Lấy giờ hiện tại chuẩn quốc tế để ghi nhận thời gian tạo khóa."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dam_bao_noi_luu_tru():
    THUMUC_NHATKY.mkdir(parents=True, exist_ok=True)
    if not TEP_LUU_KHOA.exists():
        TEP_LUU_KHOA.write_text(json.dumps({"danh_sach_khoa": {}, "id_khoa_dang_dung": None}, indent=2), encoding="utf-8")
    if not TEP_NHATKY_HOAT_DONG.exists():
        TEP_NHATKY_HOAT_DONG.write_text("", encoding="utf-8")


def _doc_du_lieu_luu_tru() -> dict:
    _dam_bao_noi_luu_tru()
    return json.loads(TEP_LUU_KHOA.read_text(encoding="utf-8"))


def _luu_du_lieu(du_lieu: dict):
    TEP_LUU_KHOA.write_text(json.dumps(du_lieu, ensure_ascii=False, indent=2), encoding="utf-8")


def _ghi_nhat_ky(su_kien: str):
    with TEP_NHATKY_HOAT_DONG.open("a", encoding="utf-8") as f:
        f.write(f"[{_lay_gio_hien_tai_utc()}] {su_kien}\n")


def tao_cap_khoa_ban_dau(id_khoa: str = ID_KHOA_MAC_DINH, ten_thuat_toan_di: str = "Dilithium2"):
    du_lieu_luu = _doc_du_lieu_luu_tru()
    if id_khoa in du_lieu_luu.get("danh_sach_khoa", {}):
        return

    khoa_ed = ed25519_impl.tao_cap_khoa_ed25519()
    khoa_di = dilithium_impl.tao_cap_khoa_dilithium(ten_thuat_toan_di)

    chu_khoa_bi_mat_ed = ed25519_impl.xuat_khoa_bi_mat_ra_chu(khoa_ed.khoa_bi_mat).decode("utf-8")
    chu_khoa_cong_khai_ed = ed25519_impl.xuat_khoa_cong_khai_ra_chu(khoa_ed.khoa_cong_khai).decode("utf-8")
    chu_khoa_bi_mat_di = khoa_di.khoa_bi_mat.hex()
    chu_khoa_cong_khai_di = dilithium_impl.bien_khoa_cong_khai_thanh_chu(khoa_di.khoa_cong_khai)

    if "danh_sach_khoa" not in du_lieu_luu:
        du_lieu_luu["danh_sach_khoa"] = {}

    du_lieu_luu["danh_sach_khoa"][id_khoa] = {
        "ngay_tao": _lay_gio_hien_tai_utc(),
        "trang_thai": "dang_hoat_dong",
        "ed25519": {
            "khoa_bi_mat_chu": chu_khoa_bi_mat_ed,
            "khoa_cong_khai_chu": chu_khoa_cong_khai_ed,
        },
        "dilithium": {
            "ten_thuat_toan": ten_thuat_toan_di,
            "khoa_bi_mat_hex": chu_khoa_bi_mat_di,
            "khoa_cong_khai_b64": chu_khoa_cong_khai_di,
        }
    }
    du_lieu_luu["id_khoa_dang_dung"] = id_khoa
    _luu_du_lieu(du_lieu_luu)
    _ghi_nhat_ky(f"Đã tạo cặp khóa mới có tên: {id_khoa}")


def lay_id_khoa_dang_dung() -> str:
    du_lieu_luu = _doc_du_lieu_luu_tru()
    id_khoa = du_lieu_luu.get("id_khoa_dang_dung")
    if not id_khoa:
        raise RuntimeError("Hệ thống chưa ghi nhận đang dùng khóa nào")
    return id_khoa


def lay_khoa_ky_hien_tai() -> dict:
    du_lieu_luu = _doc_du_lieu_luu_tru()
    id_khoa = du_lieu_luu.get("id_khoa_dang_dung")
    if not id_khoa or id_khoa not in du_lieu_luu.get("danh_sach_khoa", {}):
        raise RuntimeError("Không tìm thấy khóa ký (khóa bí mật) hiện hành")
    thong_tin_khoa = du_lieu_luu["danh_sach_khoa"][id_khoa]
    return {"id_khoa": id_khoa, **thong_tin_khoa}


def lay_khoa_cong_khai(id_khoa: str) -> dict:
    du_lieu_luu = _doc_du_lieu_luu_tru()
    if id_khoa not in du_lieu_luu.get("danh_sach_khoa", {}):
        raise KeyError(f"Không tồn tại khóa nào có tên: {id_khoa}")
    thong_tin_khoa = du_lieu_luu["danh_sach_khoa"][id_khoa]
    return {
        "khoa_cong_khai_ed_chu": thong_tin_khoa["ed25519"]["khoa_cong_khai_chu"],
        "khoa_cong_khai_di_b64": thong_tin_khoa["dilithium"]["khoa_cong_khai_b64"],
        "thuat_toan_di": thong_tin_khoa["dilithium"]["ten_thuat_toan"],
    }


def lay_khoa_bi_mat_de_ky() -> dict:
    khoa_hien_tai = lay_khoa_ky_hien_tai()
    return {
        "id_khoa": khoa_hien_tai["id_khoa"],
        "khoa_bi_mat_ed_chu": khoa_hien_tai["ed25519"]["khoa_bi_mat_chu"],
        "khoa_bi_mat_di_hex": khoa_hien_tai["dilithium"]["khoa_bi_mat_hex"],
        "thuat_toan_di": khoa_hien_tai["dilithium"]["ten_thuat_toan"],
    }