from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Dict


SUPPORTED_INTEGRITY_HASHES = {
    'shake128': 'SHAKE128-256',
}

SUPPORTED_SIGNATURE_HASHES = {
    'sha256': 'SHA-256',
}


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))


def shake128(data: bytes, length: int = 32) -> bytes:
    h = hashlib.shake_128()
    h.update(data)
    return h.digest(length)


def shake256(data: bytes, length: int = 64) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)


def compute_integrity_digest(data: bytes, algorithm: str = 'sha256', length: int = 32) -> bytes:
    algo = (algorithm or 'sha256').lower()
    if algo == 'shake256':
        return shake256(data, length=length)
    raise ValueError(f'Unsupported integrity hash: {algorithm}')


@dataclass
class Timings:
    items: Dict[str, int]

    def ms(self, k: str) -> float:
        return self.items[k] / 1e6

    def to_json(self) -> str:
        return json.dumps({k: v for k, v in self.items.items()}, indent=2)


class Timer:
    def __init__(self) -> None:
        self._t0: int | None = None

    def start(self) -> None:
        self._t0 = time.perf_counter_ns()

    def stop(self) -> int:
        if self._t0 is None:
            raise RuntimeError('Timer was not started')
        dt = time.perf_counter_ns() - self._t0
        self._t0 = None
        return dt

def kdf_shake256(shared_secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Thay thế HKDF-SHA256 bằng SHAKE-256 để phái sinh khóa"""
    h = hashlib.shake_256()
    h.update(shared_secret + salt + info)
    return h.digest(length)