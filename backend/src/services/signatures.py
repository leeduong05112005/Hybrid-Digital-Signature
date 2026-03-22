from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from src.crypto import key_manager
from src.crypto import dilithium_impl, ed25519_impl
from src.crypto.utils import b64d, b64e, compute_integrity_digest

ALGORITHMS = {
    "thuat-toan-1": "Ed25519",
    "thuat-toan-2": "Dilithium2",
}

SHAKE = {
    "shake256": "SHAKE-256 (tiêu chuẩn)",
}

_ARTIFACT_VERSION = "3.0"


def _canonical_json(obj: dict) -> bytes:
    """
    Chuẩn hóa JSON để dữ liệu ký luôn ổn định:
    - sort_keys=True
    - separators tối giản
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _build_signed_manifest(
    *,
    payload: bytes,
    integrity_hash_algorithm: str,
    original_filename: str | None = None,
    file_type: str | None = None,
) -> dict:
    digest = compute_integrity_digest(payload, integrity_hash_algorithm, length=32)

    return {
        "artifact_version": _ARTIFACT_VERSION,
        "message_b64": b64e(payload),
        "integrity_digest_hex": digest.hex(),
        "integrity_hash_algorithm": integrity_hash_algorithm,
        "payload_size": len(payload),
        "original_filename": original_filename or "",
        "file_type": file_type or "application/octet-stream",
    }


@dataclass
class SignatureArtifact:
    message_b64: str
    integrity_digest_hex: str
    signatures: list
    signature_size: int
    sign_time_ms: float = 0.0
    artifact_version: str = _ARTIFACT_VERSION
    integrity_hash_algorithm: str = "shake256"
    payload_size: int = 0
    original_filename: str = ""
    file_type: str = "application/octet-stream"

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def sign_payload(
    *,
    payload: bytes,
    integrity_hash_algorithm: str,
    original_filename: str | None = None,
    file_type: str | None = None,
) -> SignatureArtifact:
    start_time = time.time()

    try:
        signing_keys = key_manager.get_private_keys_for_signing()
    except Exception:
        key_manager.create_initial_keypair()
        signing_keys = key_manager.get_private_keys_for_signing()

    key_id = signing_keys["key_id"]

    manifest = _build_signed_manifest(
        payload=payload,
        integrity_hash_algorithm=integrity_hash_algorithm,
        original_filename=original_filename,
        file_type=file_type,
    )
    signed_bytes = _canonical_json(manifest)

    ed_private = ed25519_impl.load_private_pem(signing_keys["ed_private_pem"].encode("utf-8"))
    sig_ed = ed25519_impl.sign(ed_private, signed_bytes)

    di_private = bytes.fromhex(signing_keys["di_private_hex"])
    sig_di = dilithium_impl.sign(di_private, signed_bytes, signing_keys["di_algorithm"])

    signatures = [
        {
            "alg": "ed25519",
            "sig": b64e(sig_ed),
            "kid": key_id,
        },
        {
            "alg": "dilithium2",
            "sig": b64e(sig_di),
            "kid": key_id,
        },
    ]

    signature_size = len(sig_ed) + len(sig_di)
    end_time = time.time()

    return SignatureArtifact(
        message_b64=manifest["message_b64"],
        integrity_digest_hex=manifest["integrity_digest_hex"],
        signatures=signatures,
        signature_size=signature_size,
        sign_time_ms=round((end_time - start_time) * 1000, 2),
        artifact_version=manifest["artifact_version"],
        integrity_hash_algorithm=manifest["integrity_hash_algorithm"],
        payload_size=manifest["payload_size"],
        original_filename=manifest["original_filename"],
        file_type=manifest["file_type"],
    )


def append_signature(artifact_bytes: bytes) -> dict:
    """
    Ký bổ sung lên đúng manifest đã có sẵn, không được tạo ra dữ liệu ký khác.
    """
    start_time = time.time()

    try:
        data = json.loads(artifact_bytes.decode("utf-8"))
    except Exception:
        raise ValueError("File chữ ký không phải JSON hợp lệ")

    try:
        signing_keys = key_manager.get_private_keys_for_signing()
    except Exception:
        key_manager.create_initial_keypair()
        signing_keys = key_manager.get_private_keys_for_signing()

    key_id = signing_keys["key_id"]

    manifest = {
        "artifact_version": data.get("artifact_version", _ARTIFACT_VERSION),
        "message_b64": data["message_b64"],
        "integrity_digest_hex": data["integrity_digest_hex"],
        "integrity_hash_algorithm": data.get("integrity_hash_algorithm", "shake256"),
        "payload_size": data.get("payload_size", len(b64d(data["message_b64"]))),
        "original_filename": data.get("original_filename", ""),
        "file_type": data.get("file_type", "application/octet-stream"),
    }
    signed_bytes = _canonical_json(manifest)

    ed_private = ed25519_impl.load_private_pem(signing_keys["ed_private_pem"].encode("utf-8"))
    sig_ed = ed25519_impl.sign(ed_private, signed_bytes)
    new_sig_ed = {
        "alg": "ed25519",
        "sig": b64e(sig_ed),
        "kid": key_id,
    }

    di_private = bytes.fromhex(signing_keys["di_private_hex"])
    sig_di = dilithium_impl.sign(di_private, signed_bytes, signing_keys["di_algorithm"])
    new_sig_di = {
        "alg": "dilithium2",
        "sig": b64e(sig_di),
        "kid": key_id,
    }

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    data.setdefault("signatures", []).extend([new_sig_ed, new_sig_di])
    data["signature_size"] = data.get("signature_size", 0) + len(sig_ed) + len(sig_di)
    data["sign_time_ms"] = round(data.get("sign_time_ms", 0.0) + elapsed_ms, 2)

    data["artifact_version"] = manifest["artifact_version"]
    data["integrity_hash_algorithm"] = manifest["integrity_hash_algorithm"]
    data["payload_size"] = manifest["payload_size"]
    data["original_filename"] = manifest["original_filename"]
    data["file_type"] = manifest["file_type"]

    return data


def verify_artifact(
    artifact_bytes: bytes,
    payload: bytes,
    external_pubkeys: list[dict] | None = None,
    mode: str = "all",
) -> Tuple[bool, dict]:
    start_time = time.time()

    try:
        data = json.loads(artifact_bytes.decode("utf-8"))
    except Exception:
        return False, {"Lí do": "File chữ ký không phải JSON hợp lệ"}

    try:
        embedded_payload = b64d(data.get("message_b64", ""))
    except Exception:
        return False, {"Lí do": "message_b64 trong artifact không hợp lệ"}

    if embedded_payload != payload:
        return False, {
            "Lí do": "Nội dung dữ liệu xác thực không trùng khớp hoàn toàn với dữ liệu đã được ký"
        }

    payload_size = data.get("payload_size")
    if payload_size is not None and payload_size != len(payload):
        return False, {"Lí do": "Kích thước dữ liệu đã thay đổi"}

    integrity_algo = data.get("integrity_hash_algorithm", "shake256")
    recomputed = compute_integrity_digest(payload, integrity_algo, length=32)
    if recomputed.hex() != data.get("integrity_digest_hex"):
        return False, {
            "Lí do": "Mã băm không khớp (Dữ liệu đã bị thay đổi hoặc bạn chọn sai dữ liệu)"
        }

    manifest = {
        "artifact_version": data.get("artifact_version", _ARTIFACT_VERSION),
        "message_b64": data.get("message_b64", ""),
        "integrity_digest_hex": data.get("integrity_digest_hex", ""),
        "integrity_hash_algorithm": integrity_algo,
        "payload_size": data.get("payload_size", len(payload)),
        "original_filename": data.get("original_filename", ""),
        "file_type": data.get("file_type", "application/octet-stream"),
    }
    signed_bytes = _canonical_json(manifest)

    results = []

    for s in data.get("signatures", []):
        alg = s.get("alg")
        key_id = s.get("kid")

        try:
            sig_bytes = b64d(s.get("sig", ""))
        except Exception:
            results.append({
                "alg": alg,
                "valid": False,
                "key_id": key_id,
                "reason": "Chữ ký không hợp lệ (base64 lỗi)",
            })
            continue

        pub = None

        if external_pubkeys:
            for k in external_pubkeys:
                if k.get("key_id") == key_id:
                    pub = k
                    break

        if not pub:
            try:
                pub = key_manager.get_public_keys(key_id)
            except Exception:
                pub = None

        if not pub:
            results.append({
                "alg": alg,
                "valid": False,
                "key_id": key_id,
                "reason": "Không tìm thấy Public Key tương ứng",
            })
            continue

        try:
            if alg == "ed25519":
                ok = ed25519_impl.verify(
                    ed25519_impl.load_public_pem(pub["ed_public_pem"].encode("utf-8")),
                    signed_bytes,
                    sig_bytes,
                )
            elif alg == "dilithium2":
                ok = dilithium_impl.verify(
                    dilithium_impl.load_public_key(pub["di_public_b64"]),
                    signed_bytes,
                    sig_bytes,
                    pub["di_algorithm"],
                )
            else:
                ok = False
        except Exception:
            ok = False

        results.append({
            "alg": alg,
            "valid": ok,
            "key_id": key_id,
        })

    verification_time_ms = round((time.time() - start_time) * 1000, 2)

    if mode == "any":
        valid = any(r["valid"] for r in results)
    else:
        valid = all(r["valid"] for r in results) if results else False

    return valid, {
        "details": results,
        "verification_time_ms": verification_time_ms,
        "signature_size": data.get("signature_size", 0),
    }


def save_artifact(artifact: SignatureArtifact, output_dir: Path, stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{stem}.sig.json"
    target.write_text(
        json.dumps(artifact.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    return target