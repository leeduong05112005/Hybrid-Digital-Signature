from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_cors import CORS
from config import APP_NAME, APP_VERSION, OUTPUTS_DIR, STATIC_DIR, TEMPLATES_DIR
from src.services.signatures import ky_dulieu, them_signature, xac_thuc_signature, luu_signature
from src.crypto import key_manager

app = Flask(__name__, template_folder=str(TEMPLATES_DIR), static_folder=str(STATIC_DIR))
app.secret_key = __import__("config").SECRET_KEY
CORS(app)

def pdf_hop_le(ten_tep: str, dulieu: bytes) -> bool:
    return bool(ten_tep) and ten_tep.lower().endswith(".pdf") and dulieu.startswith(b"%PDF-")

@app.context_processor
def dua_bien_vao_giao_dien():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "current_year": datetime.now().year,
    }

@app.route("/")
def trang_chu():
    return redirect(url_for("trang_ky_tai_lieu"))

@app.route("/sign")
def trang_ky_tai_lieu():
    return render_template("sign.html")

@app.route("/verify")
def trang_kiem_tra():
    return render_template("verify.html")

@app.route("/api/sign", methods=["POST"])
def api_thuc_hien_ky():
    try:
        tep_tai_len = request.files.get("message_file")
        van_ban = (request.form.get("message_text") or "").strip()
        current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if tep_tai_len and tep_tai_len.filename and tep_tai_len.filename.endswith(".sig.json"):
            ket_qua = them_signature(tep_tai_len.read())
            ten_goc = f"{Path(tep_tai_len.filename).stem.replace('.sig', '')}_appended_{current_time}"
            
            OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
            duong_dan_xuat = OUTPUTS_DIR / f"{ten_goc}.sig.json"
            duong_dan_xuat.write_text(json.dumps(ket_qua, indent=2, ensure_ascii=False), encoding="utf-8")
            return jsonify({
                "success": True,
                "signature_size": ket_qua.get("signature_size"),
                "sign_time_ms": ket_qua.get("sign_time_ms"),
                "integrity_digest_hex": ket_qua.get("integrity_digest_hex"),
                "download_url": url_for("tai_file_ket_qua", filename=duong_dan_xuat.name),
                "download_pub_url": url_for("publicKey", key_id=ket_qua["signatures"][-1]["kid"]),
                "artifact": ket_qua,
            })
            
        if tep_tai_len and tep_tai_len.filename:
            dulieu = tep_tai_len.read()
            if not pdf_hop_le(tep_tai_len.filename, dulieu):
                return jsonify({"success": False, "error": "Chỉ cho phép tải lên file PDF hợp lệ"}), 400
            
            ten_goc = f"{Path(tep_tai_len.filename).stem}_{current_time}"
            ten_tep_goc, loai_tep = tep_tai_len.filename, "application/pdf"
        elif van_ban:
            dulieu = van_ban.encode("utf-8")
            ten_goc, ten_tep_goc, loai_tep = f"message_{current_time}", "message.txt", "text/plain"
        else:
            return jsonify({"success": False, "error": "Bạn chưa cung cấp file PDF hoặc văn bản để ký"}), 400
            
        ket_qua_ky = ky_dulieu(dulieu, "shake256", ten_tep_goc, loai_tep)
        duong_dan_xuat = luu_signature(ket_qua_ky, OUTPUTS_DIR, ten_goc)
        
        # SỬA LỖI: .signature -> .signatures
        return jsonify({
            "success": True,
            "signature_size": ket_qua_ky.signature_size,
            "sign_time_ms": ket_qua_ky.thoi_gian_ky_ms,
            "integrity_digest_hex": ket_qua_ky.ma_bam_toan_ven,
            "download_url": url_for("tai_file_ket_qua", filename=duong_dan_xuat.name),
            "download_pub_url": url_for("publicKey", key_id=ket_qua_ky.signatures[0]["kid"]),
            "artifact": ket_qua_ky.to_dict(),
        })

    except Exception as e:
        import traceback
        traceback.print_exc() # In lỗi ra Terminal để Dương dễ theo dõi
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/verify", methods=["POST"])
def api_kiem_tra_signature():
    try:
        tep_signature = request.files.get("signature_file")
        if not tep_signature:
            return jsonify({"success": False, "error": "Thiếu file chữ ký (có đuôi .sig.json)"}), 400
        tep_publicKey = request.files.get("public_key_file")
        key_list = []
        if tep_publicKey:
            try:
                dulieu_khoa = json.loads(tep_publicKey.read().decode("utf-8"))
                key_list = dulieu_khoa if isinstance(dulieu_khoa, list) else [dulieu_khoa]
            except Exception:
                return jsonify({"success": False, "error": "File Chìa khóa công khai không đọc được"}), 400
                
        tep_tai_len = request.files.get("message_file")
        van_ban = (request.form.get("message_text") or "").strip()
        if tep_tai_len and tep_tai_len.filename:
            dulieu = tep_tai_len.read()
            if not pdf_hop_le(tep_tai_len.filename, dulieu):
                return jsonify({"success": False, "error": "Chỉ hỗ trợ kiểm tra file PDF hợp lệ"}), 400
        elif van_ban:
            dulieu = van_ban.encode("utf-8")
        else:
            return jsonify({"success": False, "error": "Bạn chưa cung cấp file PDF gốc hoặc văn bản để đối chiếu"}), 400
            
        hop_le, chi_tiet = xac_thuc_signature(tep_signature.read(), dulieu, key_list)
        return jsonify({
            "success": True,
            "verified": hop_le,
            "details": chi_tiet,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/outputs/<path:filename>")
def tai_file_ket_qua(filename):
    return send_from_directory(str(OUTPUTS_DIR), filename, as_attachment=True)

@app.route("/api/pubkey/<key_id>")
def publicKey(key_id):
    try:
        pub_key_data = key_manager.lay_public_key(key_id)
        pub_key_data["key_id"] = key_id 
        return app.response_class(
            response=json.dumps(pub_key_data, indent=2, ensure_ascii=False),
            status=200,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=pubkey_{key_id}.json"},
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 404