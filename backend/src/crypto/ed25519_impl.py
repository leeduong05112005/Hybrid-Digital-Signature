from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import os

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .utils import kdf_shake256

@dataclass
class Ed25519Keys:
    privateKey: ed25519.Ed25519PrivateKey
    publicKey: ed25519.Ed25519PublicKey

def tao_ed25519() -> Ed25519Keys:
    privateKey = ed25519.Ed25519PrivateKey.generate()
    return Ed25519Keys(
        privateKey=privateKey, 
        publicKey=privateKey.public_key()
    )

def tao_signature(privateKey: ed25519.Ed25519PrivateKey, dulieu_canky: bytes) -> bytes:
    return privateKey.sign(dulieu_canky)

def check_signature(publicKey: ed25519.Ed25519PublicKey, dulieu_goc: bytes, signature: bytes) -> bool:
    try:
        publicKey.verify(signature, dulieu_goc)
        return True 
    except Exception:
        return False

@dataclass
class X25519Keys:
    privateKey: x25519.X25519PrivateKey
    publicKey: x25519.X25519PublicKey

def tao_x25519() -> X25519Keys:
    privateKey = x25519.X25519PrivateKey.generate()
    return X25519Keys(
        privateKey=privateKey, 
        publicKey=privateKey.public_key()
    )

def encrypt_dulieu(dulieu_ro: bytes, publicKey_nguoi_nhan: x25519.X25519PublicKey, dulieu_dinh_kem: bytes=b"") -> Tuple[bytes, bytes, bytes]:
    privateKey_tam_thoi = x25519.X25519PrivateKey.generate()
    
    share_key = privateKey_tam_thoi.exchange(publicKey_nguoi_nhan)
    encryptionKey = kdf_shake256(share_key, salt=b"x25519", info=b"aesgcm", length=32)
    
    o_khoa = AESGCM(encryptionKey)
    random = os.urandom(12)
    dulieu_mahoa = o_khoa.encrypt(random, dulieu_ro, dulieu_dinh_kem)
    
    publicKey_tam_thoi = privateKey_tam_thoi.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return publicKey_tam_thoi, random, dulieu_mahoa

def decrypt_dulieu(dulieu_mahoa: bytes, private_nguoi_nhan: x25519.X25519PrivateKey, publicKey_tam_thoi: bytes, random: bytes, dulieu_dinh_kem: bytes=b"") -> bytes:
    khoa_tam_thoi = x25519.X25519PublicKey.from_public_bytes(publicKey_tam_thoi)
    share_key = private_nguoi_nhan.exchange(khoa_tam_thoi)
    encryptionKey = kdf_shake256(share_key, salt=b"x25519", info=b"aesgcm", length=32)
    
    o_khoa = AESGCM(encryptionKey)
    return o_khoa.decrypt(random, dulieu_mahoa, dulieu_dinh_kem)

def publicKey_to_pem(publicKey: ed25519.Ed25519PublicKey) -> bytes:
    return publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def privateKey_to_pem(privateKey: ed25519.Ed25519PrivateKey, password_protection: bytes | None = None) -> bytes:
    cach_bao_ve = serialization.NoEncryption() if password_protection is None else serialization.BestAvailableEncryption(password_protection)
    return privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=cach_bao_ve
    )

def pem_to_public_key(chu_chua_khoa: bytes) -> ed25519.Ed25519PublicKey:
    khoa = serialization.load_pem_public_key(chu_chua_khoa)
    if not isinstance(khoa, ed25519.Ed25519PublicKey):
        raise TypeError("Loại khóa công khai không hợp lệ")
    return khoa

def pem_to_private_key(chu_chua_khoa: bytes, password: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    khoa_private = serialization.load_pem_private_key(chu_chua_khoa, password=password)
    if not isinstance(khoa_private, ed25519.Ed25519PrivateKey):
        raise TypeError("Loại khóa bí mật không hợp lệ")
    return khoa_private