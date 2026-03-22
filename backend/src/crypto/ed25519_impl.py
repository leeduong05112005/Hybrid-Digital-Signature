from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import os

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .utils import kdf_shake256

@dataclass
class cap_khoa_ed25519:
    khoa_bi_mat: ed25519.Ed25519PrivateKey
    khoa_cong_khai: ed25519.Ed25519PublicKey

def tao_cap_khoa_ed25519() -> cap_khoa_ed25519:
    khoa_bi_mat_moi = ed25519.Ed25519PrivateKey.generate()
    return cap_khoa_ed25519(
        khoa_bi_mat=khoa_bi_mat_moi, 
        khoa_cong_khai=khoa_bi_mat_moi.public_key()
    )

def tao_chu_ky(khoa_bi_mat: ed25519.Ed25519PrivateKey, du_lieu_can_ky: bytes) -> bytes:
    return khoa_bi_mat.sign(du_lieu_can_ky)

def kiem_tra_chu_ky(khoa_cong_khai: ed25519.Ed25519PublicKey, du_lieu_goc: bytes, chu_ky: bytes) -> bool:
    try:
        khoa_cong_khai.verify(chu_ky, du_lieu_goc)
        return True 
    except Exception:
        return False

@dataclass
class cap_khoa_x25519:
    khoa_bi_mat: x25519.X25519PrivateKey
    khoa_cong_khai: x25519.X25519PublicKey

def tao_cap_khoa_x25519() -> cap_khoa_x25519:
    khoa_bi_mat_moi = x25519.X25519PrivateKey.generate()
    return cap_khoa_x25519(
        khoa_bi_mat=khoa_bi_mat_moi, 
        khoa_cong_khai=khoa_bi_mat_moi.public_key()
    )

def ma_hoa_du_lieu(du_lieu_ro: bytes, khoa_cong_khai_nguoi_nhan: x25519.X25519PublicKey, du_lieu_dinh_kem: bytes=b"") -> Tuple[bytes, bytes, bytes]:
    khoa_bi_mat_tam_thoi = x25519.X25519PrivateKey.generate()
    
    chia_khoa_chung = khoa_bi_mat_tam_thoi.exchange(khoa_cong_khai_nguoi_nhan)
    chia_khoa_ma_hoa = kdf_shake256(chia_khoa_chung, salt=b"x25519", info=b"aesgcm", length=32)
    
    o_khoa = AESGCM(chia_khoa_ma_hoa)
    so_ngau_nhien = os.urandom(12)
    du_lieu_da_ma_hoa = o_khoa.encrypt(so_ngau_nhien, du_lieu_ro, du_lieu_dinh_kem)
    
    khoa_cong_khai_tam_thoi = khoa_bi_mat_tam_thoi.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return khoa_cong_khai_tam_thoi, so_ngau_nhien, du_lieu_da_ma_hoa

def giai_ma_du_lieu(du_lieu_da_ma_hoa: bytes, khoa_bi_mat_nguoi_nhan: x25519.X25519PrivateKey, khoa_cong_khai_tam_thoi: bytes, so_ngau_nhien: bytes, du_lieu_dinh_kem: bytes=b"") -> bytes:
    khoa_tam_thoi = x25519.X25519PublicKey.from_public_bytes(khoa_cong_khai_tam_thoi)
    chia_khoa_chung = khoa_bi_mat_nguoi_nhan.exchange(khoa_tam_thoi)
    chia_khoa_ma_hoa = kdf_shake256(chia_khoa_chung, salt=b"x25519", info=b"aesgcm", length=32)
    
    o_khoa = AESGCM(chia_khoa_ma_hoa)
    return o_khoa.decrypt(so_ngau_nhien, du_lieu_da_ma_hoa, du_lieu_dinh_kem)

def xuat_khoa_cong_khai_ra_chu(khoa_cong_khai: ed25519.Ed25519PublicKey) -> bytes:
    return khoa_cong_khai.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def xuat_khoa_bi_mat_ra_chu(khoa_bi_mat: ed25519.Ed25519PrivateKey, mat_khau_bao_ve: bytes | None = None) -> bytes:
    cach_bao_ve = serialization.NoEncryption() if mat_khau_bao_ve is None else serialization.BestAvailableEncryption(mat_khau_bao_ve)
    return khoa_bi_mat.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=cach_bao_ve
    )

def doc_khoa_cong_khai_tu_chu(chu_chua_khoa: bytes) -> ed25519.Ed25519PublicKey:
    khoa = serialization.load_pem_public_key(chu_chua_khoa)
    if not isinstance(khoa, ed25519.Ed25519PublicKey):
        raise TypeError("Loại khóa công khai không hợp lệ")
    return khoa

def doc_khoa_bi_mat_tu_chu(chu_chua_khoa: bytes, mat_khau_bao_ve: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    khoa = serialization.load_pem_private_key(chu_chua_khoa, password=mat_khau_bao_ve)
    if not isinstance(khoa, ed25519.Ed25519PrivateKey):
        raise TypeError("Loại khóa bí mật không hợp lệ")
    return khoa