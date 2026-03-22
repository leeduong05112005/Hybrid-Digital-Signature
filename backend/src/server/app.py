from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_cors import CORS
from config import APP_NAME, APP_VERSION, OUTPUTS_DIR, STATIC_DIR, TEMPLATES_DIR
from src.services.signatures import ky_du_lieu, them_chu_ky, xac_thuc_chu_ky, luu_chu_ky
from src.crypto import key_manager

app = Flask(__name__, template_folder=str(TEMPLATES_DIR), static_folder=str(STATIC_DIR))
app.secret_key = __import__("config").SECRET_KEY
CORS(app)

def _la_pdf_hop_le(ten_tep: str, du_lieu: bytes) -> bool:
    """Kiểm tra xem file tải lên có đúng chuẩn là file PDF không."""
    return bool(ten_tep) and ten_tep.lower().endswith(".pdf") and du_lieu.startswith(b"%PDF-")

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
        thoi_gian_hien_tai = datetime.now().strftime('%Y%m%d_%H%M%S')
        if tep_tai_len and tep_tai_len.filename and tep_tai_len.filename.endswith(".sig.json"):
            ket_qua = them_chu_ky(tep_tai_len.read())
            ten_goc = f"{Path(tep_tai_len.filename).stem.replace('.sig', '')}_appended_{thoi_gian_hien_tai}"
            
            OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
            duong_dan_xuat = OUTPUTS_DIR / f"{ten_goc}.sig.json"
            duong_dan_xuat.write_text(json.dumps(ket_qua, indent=2, ensure_ascii=False), encoding="utf-8")
            return jsonify({
                "success": True,
                "signature_size": ket_qua.get("signature_size"),
                "sign_time_ms": ket_qua.get("sign_time_ms"),
                "integrity_digest_hex": ket_qua.get("integrity_digest_hex"),
                "download_url": url_for("tai_file_ket_qua", filename=duong_dan_xuat.name),
                "download_pub_url": url_for("tai_khoa_cong_khai", key_id=ket_qua["signatures"][-1]["kid"]),
                "artifact": ket_qua,
            })
        if tep_tai_len and tep_tai_len.filename:
            du_lieu = tep_tai_len.read()
            if not _la_pdf_hop_le(tep_tai_len.filename, du_lieu):
                return jsonify({"success": False, "error": "Chỉ cho phép tải lên file PDF hợp lệ"}), 400
            
            ten_goc = f"{Path(tep_tai_len.filename).stem}_{thoi_gian_hien_tai}"
            ten_tep_goc, loai_tep = tep_tai_len.filename, "application/pdf"
        elif van_ban:
            du_lieu = van_ban.encode("utf-8")
            ten_goc, ten_tep_goc, loai_tep = f"message_{thoi_gian_hien_tai}", "message.txt", "text/plain"
        else:
            return jsonify({"success": False, "error": "Bạn chưa cung cấp file PDF hoặc văn bản để ký"}), 400
        ket_qua_ky = ky_du_lieu(du_lieu, "shake256", ten_tep_goc, loai_tep)
        duong_dan_xuat = luu_chu_ky(ket_qua_ky, OUTPUTS_DIR, ten_goc)
        return jsonify({
            "success": True,
            "signature_size": ket_qua_ky.kich_thuoc_chu_ky,
            "sign_time_ms": ket_qua_ky.thoi_gian_ky_ms,
            "integrity_digest_hex": ket_qua_ky.ma_bam_toan_ven,
            "download_url": url_for("tai_file_ket_qua", filename=duong_dan_xuat.name),
            "download_pub_url": url_for("tai_khoa_cong_khai", key_id=ket_qua_ky.chu_ky[0]["kid"]),
            "artifact": ket_qua_ky.to_dict(),
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/verify", methods=["POST"])
def api_kiem_tra_chu_ky():
    try:
        tep_chu_ky = request.files.get("signature_file")
        if not tep_chu_ky:
            return jsonify({"success": False, "error": "Thiếu file chữ ký (có đuôi .sig.json)"}), 400
        tep_khoa_cong_khai = request.files.get("public_key_file")
        danh_sach_khoa = []
        
        if tep_khoa_cong_khai:
            try:
                du_lieu_khoa = json.loads(tep_khoa_cong_khai.read().decode("utf-8"))
                danh_sach_khoa = du_lieu_khoa if isinstance(du_lieu_khoa, list) else [du_lieu_khoa]
            except Exception:
                return jsonify({"success": False, "error": "File Chìa khóa công khai không đọc được"}), 400
        tep_tai_len = request.files.get("message_file")
        van_ban = (request.form.get("message_text") or "").strip()
        if tep_tai_len and tep_tai_len.filename:
            du_lieu = tep_tai_len.read()
            if not _la_pdf_hop_le(tep_tai_len.filename, du_lieu):
                return jsonify({"success": False, "error": "Chỉ hỗ trợ kiểm tra file PDF hợp lệ"}), 400
        elif van_ban:
            du_lieu = van_ban.encode("utf-8")
        else:
            return jsonify({"success": False, "error": "Bạn chưa cung cấp file PDF gốc hoặc văn bản để đối chiếu"}), 400
        hop_le, chi_tiet = xac_thuc_chu_ky(tep_chu_ky.read(), du_lieu, danh_sach_khoa)
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
def tai_khoa_cong_khai(key_id):
    try:
        khoa_cong_khai = key_manager.lay_khoa_cong_khai(key_id)
        khoa_cong_khai["key_id"] = key_id 
        return app.response_class(
            response=json.dumps(khoa_cong_khai, indent=2, ensure_ascii=False),
            status=200,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=pubkey_{key_id}.json"},
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 404