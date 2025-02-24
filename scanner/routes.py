from flask import request, jsonify, render_template  # render_template eklenmeli
from . import scanner_bp
from .scanner import scan_website 

@scanner_bp.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "URL belirtilmedi"}), 400

    scan_results = scan_website(url)
    return jsonify(scan_results)

@scanner_bp.route('/')
def index():
    return render_template('report.html')
