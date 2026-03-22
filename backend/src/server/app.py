from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_cors import CORS

from config import APP_NAME, APP_VERSION, OUTPUTS_DIR, STATIC_DIR, TEMPLATES_DIR
from src.services.signatures import sign_payload, append_signature, verify_artifact, save_artifact
from src.crypto import key_manager

app = Flask(__name__, template_folder=str(TEMPLATES_DIR), static_folder=str(STATIC_DIR))
app.secret_key = __import__("config").SECRET_KEY
CORS(app)


def _is_pdf(filename: str, payload: bytes) -> bool:
    """
    Chỉ chấp nhận file PDF thật khi user upload file:
    - đuôi .pdf
    - bytes đầu bắt đầu bằng %PDF-
    """
    if not filename:
        return False
    return filename.lower().endswith(".pdf") and payload.startswith(b"%PDF-")


@app.context_processor
def inject_globals():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "current_year": datetime.now().year,
    }


@app.route("/")
def index():
    return redirect(url_for("sign_page"))


@app.route("/sign")
def sign_page():
    return render_template("sign.html")


@app.route("/verify")
def verify_page():
    return render_template("verify.html")


@app.route("/api/sign", methods=["POST"])
def api_sign():
    try:
        upload = request.files.get("message_file")
        text = (request.form.get("message_text") or "").strip()

        if upload and upload.filename and upload.filename.endswith(".sig.json"):
            artifact_bytes = upload.read()
            updated_artifact = append_signature(artifact_bytes)

            stem = Path(upload.filename).stem.replace(".sig", "")
            stem += f"_appended_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
            output_path = OUTPUTS_DIR / f"{stem}.sig.json"
            output_path.write_text(
                json.dumps(updated_artifact, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

            return jsonify({
                "success": True,
                "signature_size": updated_artifact.get("signature_size"),
                "sign_time_ms": updated_artifact.get("sign_time_ms"),
                "integrity_digest_hex": updated_artifact.get("integrity_digest_hex"),
                "download_url": url_for("download_output", filename=output_path.name),
                "download_pub_url": url_for("download_pubkey", key_id=updated_artifact["signatures"][-1]["kid"]),
                "artifact": updated_artifact,
            })

        if upload and upload.filename:
            payload = upload.read()

            if not _is_pdf(upload.filename, payload):
                return jsonify({
                    "success": False,
                    "error": "Chỉ cho phép upload file PDF hợp lệ",
                }), 400

            stem = Path(upload.filename).stem + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            original_filename = upload.filename
            file_type = "application/pdf"

        elif text:
            payload = text.encode("utf-8")
            stem = "message_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            original_filename = "message.txt"
            file_type = "text/plain"

        else:
            return jsonify({
                "success": False,
                "error": "Thiếu dữ liệu (File PDF hoặc văn bản)",
            }), 400

        artifact = sign_payload(
            payload=payload,
            integrity_hash_algorithm="shake256",
            original_filename=original_filename,
            file_type=file_type,
        )
        output_path = save_artifact(artifact, OUTPUTS_DIR, stem)

        return jsonify({
            "success": True,
            "signature_size": artifact.signature_size,
            "sign_time_ms": artifact.sign_time_ms,
            "integrity_digest_hex": artifact.integrity_digest_hex,
            "download_url": url_for("download_output", filename=output_path.name),
            "download_pub_url": url_for("download_pubkey", key_id=artifact.signatures[0]["kid"]),
            "artifact": artifact.to_dict(),
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/verify", methods=["POST"])
def api_verify():
    try:
        sig_file = request.files.get("signature_file")
        if not sig_file:
            return jsonify({
                "success": False,
                "error": "Thiếu file chữ ký (.sig.json)",
            }), 400

        pub_file = request.files.get("public_key_file")
        pubkeys = []
        if pub_file:
            try:
                parsed = json.loads(pub_file.read().decode("utf-8"))
                pubkeys = parsed if isinstance(parsed, list) else [parsed]
            except Exception:
                return jsonify({
                    "success": False,
                    "error": "Tệp Public Key không hợp lệ",
                }), 400

        upload = request.files.get("message_file")
        text = (request.form.get("message_text") or "").strip()

        if upload and upload.filename:
            payload = upload.read()

            if not _is_pdf(upload.filename, payload):
                return jsonify({
                    "success": False,
                    "error": "Chỉ cho phép xác thực file PDF hợp lệ khi dùng chế độ tải file",
                }), 400

        elif text:
            payload = text.encode("utf-8")

        else:
            return jsonify({
                "success": False,
                "error": "Thiếu file PDF gốc hoặc văn bản để xác thực",
            }), 400

        ok, details = verify_artifact(
            artifact_bytes=sig_file.read(),
            payload=payload,
            external_pubkeys=pubkeys,
            mode="all",
        )

        return jsonify({
            "success": True,
            "verified": ok,
            "details": details,
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/outputs/<path:filename>")
def download_output(filename):
    return send_from_directory(str(OUTPUTS_DIR), filename, as_attachment=True)

@app.route("/api/pubkey/<key_id>")
def download_pubkey(key_id):
    try:
        pubkeys = key_manager.get_public_keys(key_id)
        pubkeys["key_id"] = key_id 
        return app.response_class(
            response=json.dumps(pubkeys, indent=2, ensure_ascii=False),
            status=200,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=pubkey_{key_id}.json"},
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 404