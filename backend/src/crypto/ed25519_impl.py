from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
import os

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .utils import kdf_shake256

@dataclass
class Ed25519KeyPair:
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey

def generate_ed25519() -> Ed25519KeyPair:
    priv = ed25519.Ed25519PrivateKey.generate()
    return Ed25519KeyPair(private_key=priv, public_key=priv.public_key())

def sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)

def verify(public_key: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

# For encryption, use X25519 key agreement + AES-GCM
@dataclass
class X25519KeyPair:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

def generate_x25519() -> X25519KeyPair:
    priv = x25519.X25519PrivateKey.generate()
    return X25519KeyPair(private_key=priv, public_key=priv.public_key())

def encrypt_aesgcm_x25519(plaintext: bytes,
                          receiver_public_key: x25519.X25519PublicKey,
                          aad: bytes=b"") -> Tuple[bytes, bytes, bytes]:
    eph_priv = x25519.X25519PrivateKey.generate()
    shared = eph_priv.exchange(receiver_public_key)
    key = hkdf_sha256(shared, salt=b"x25519", info=b"aesgcm", length=32)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return eph_pub_bytes, nonce, ct

def decrypt_aesgcm_x25519(ciphertext: bytes,
                          receiver_private_key: x25519.X25519PrivateKey,
                          eph_pub_bytes: bytes,
                          nonce: bytes,
                          aad: bytes=b"") -> bytes:
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared = receiver_private_key.exchange(eph_pub)
    key = hkdf_sha256(shared, salt=b"x25519", info=b"aesgcm", length=32)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def export_public_pem(public_key: ed25519.Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def export_private_pem(private_key: ed25519.Ed25519PrivateKey, password: bytes | None = None) -> bytes:
    enc = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def load_public_pem(pem: bytes) -> ed25519.Ed25519PublicKey:
    pk = serialization.load_pem_public_key(pem)
    if not isinstance(pk, ed25519.Ed25519PublicKey):
        raise TypeError("Invalid public key type")
    return pk

def load_private_pem(pem: bytes, password: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    sk = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(sk, ed25519.Ed25519PrivateKey):
        raise TypeError("Invalid private key type")
    return sk
