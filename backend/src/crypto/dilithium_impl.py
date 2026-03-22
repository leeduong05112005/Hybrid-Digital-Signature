from __future__ import annotations
import base64
from dataclasses import dataclass

try:
    import oqs
    try:
        with oqs.Signature("Dilithium2") as test_sig:
            pass
        co_san_thu_vien = True
        loi_thu_vien = ""
    except Exception as e:
        oqs = None
        co_san_thu_vien = False
        loi_thu_vien = f"Thư viện lõi liboqs không khả dụng: {e}"
except Exception as e:
    oqs = None
    co_san_thu_vien = False
    loi_thu_vien = f"Chưa cài liboqs-python hoặc bị lỗi: {e}"

@dataclass
class cap_khoa_dilithium:
    khoa_bi_mat: bytes
    khoa_cong_khai: bytes
    ten_thuat_toan: str = 'Dilithium2'

def thu_vien_da_san_sang() -> bool:
    return oqs is not None and hasattr(oqs, 'Signature')

def loi_can_cai_dat() -> str:
    return 'Thuật toán Dilithium cần liboqs-python và thư viện nền liboqs. Hãy cài đặt bằng lệnh: pip install liboqs-python'
def tao_cap_khoa_dilithium(ten_thuat_toan: str = 'Dilithium2') -> cap_khoa_dilithium:
    if oqs is None:  
        raise RuntimeError(loi_can_cai_dat())
        
    with oqs.Signature(ten_thuat_toan) as bo_cong_cu_ky:
        khoa_cong_khai_moi = bo_cong_cu_ky.generate_keypair()
        khoa_bi_mat_moi = bo_cong_cu_ky.export_secret_key()
        
    return cap_khoa_dilithium(
        khoa_bi_mat=khoa_bi_mat_moi, 
        khoa_cong_khai=khoa_cong_khai_moi, 
        ten_thuat_toan=ten_thuat_toan
    )

def tao_chu_ky(khoa_bi_mat: bytes, du_lieu_can_ky: bytes, ten_thuat_toan: str = 'Dilithium2') -> bytes:
    if oqs is None:
        raise RuntimeError(loi_can_cai_dat())
        
    with oqs.Signature(ten_thuat_toan, secret_key=khoa_bi_mat) as bo_cong_cu_ky:
        return bo_cong_cu_ky.sign(du_lieu_can_ky)
def kiem_tra_chu_ky(khoa_cong_khai: bytes, du_lieu_goc: bytes, chu_ky: bytes, ten_thuat_toan: str = 'Dilithium2') -> bool:
    if oqs is None: 
        raise RuntimeError(loi_can_cai_dat())
        
    with oqs.Signature(ten_thuat_toan) as bo_cong_cu_kiem_tra:
        return bool(bo_cong_cu_kiem_tra.verify(du_lieu_goc, chu_ky, khoa_cong_khai))

def bien_khoa_cong_khai_thanh_chu(khoa_cong_khai: bytes) -> str:
    return base64.b64encode(khoa_cong_khai).decode('ascii')
def doc_khoa_cong_khai_tu_chu(chu_chua_khoa: str) -> bytes:
    return base64.b64decode(chu_chua_khoa.encode('ascii'))

def dam_bao_thu_vien_hoat_dong():
    if not co_san_thu_vien:
        raise RuntimeError(f"Thuật toán Dilithium chưa sẵn sàng: {loi_thu_vien}")
def bien_khoa_bi_mat_thanh_chu_hex(khoa_bi_mat: bytes) -> str:
    return khoa_bi_mat.hex()

def doc_khoa_bi_mat_tu_chu_hex(chu_chua_khoa_hex: str) -> bytes:
    return bytes.fromhex(chu_chua_khoa_hex)