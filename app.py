import os
import re
import requests
import json
import base64
import time
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response
from urllib.parse import urlparse, urljoin
from validators import url as validate_url

# إعداد التطبيق مع تحديد مجلد الملفات الثابتة
app = Flask(__name__, static_folder='static')

# --- إضافة مسارات الأرشفة (Sitemap & Robots) ---
@app.route('/sitemap.xml')
def sitemap():
    try:
        # إرسال الملف مع تحديد النوع كـ XML لضمان قبول جوجل له
        response = make_response(send_from_directory(app.static_folder, 'sitemap.xml'))
        response.headers['Content-Type'] = 'application/xml'
        return response
    except Exception as e:
        return str(e), 404

@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')

# --- إعدادات المحرك (كما هي بدون تغيير) ---
SENSITIVE_PATTERNS = {
    "Credential Harvesting": r'(?i)(password|passwd|signin|login|credential|verification)',
    "Browser Exploitation": r'(?i)(eval\(|unescape\(|document\.write\(|setTimeout\(|setInterval\()',
    "Data Exfiltration": r'(?i)(XMLHttpRequest|fetch|ajax|\.post\(|\.get\()',
    "Privacy Violation": r'(?i)(navigator\.mediaDevices|getUserMedia|geolocation|cookie|localStorage)'
}

WHITELIST_DOMAINS = [
    'google.com', 'google.com.eg', 'facebook.com', 'youtube.com', 'twitter.com', 
    'x.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com', 
    'amazon.com', 'github.com', 'vercel.app', 'openai.com', 'cloudflare.com'
]

def is_trusted(url):
    domain = urlparse(url).netloc.lower().replace('www.', '')
    return any(domain == d or domain.endswith('.' + d) for d in WHITELIST_DOMAINS)

def recursive_js_analysis(html, base_url):
    """تحليل السكربتات بعمق دون الوقوع في فخ النتائج الخاطئة"""
    scripts = re.findall(r'<script.*?src=["\'](.*?)["\']', html, re.I)
    inline_scripts = re.findall(r'<script>(.*?)</script>', html, re.S | re.I)
    
    all_js = "\n".join(inline_scripts)
    
    for s_url in scripts[:3]:
        try:
            full_s_url = urljoin(base_url, s_url)
            r = requests.get(full_s_url, timeout=3, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                all_js += "\n" + r.text
        except: continue

    b64_matches = re.findall(r'["\']([A-Za-z0-9+/]{50,})={0,2}["\']', all_js)
    for b in b64_matches:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            all_js += "\n" + decoded
        except: continue

    return all_js

def perform_deep_scan(url):
    start_time = time.time()
    results = {
        "risk_score": "Low",
        "points": 0,
        "violations": [],
        "redirects": [url],
        "final_url": url,
        "analysis_time": 0
    }

    try:
        session = requests.Session()
        response = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        results["final_url"] = response.url
        results["redirects"] = [r.url for r in response.history] + [response.url]
        
        if is_trusted(results["final_url"]):
            results["analysis_time"] = round(time.time() - start_time, 2)
            return results

        html_content = response.text
        js_content = recursive_js_analysis(html_content, results["final_url"])
        full_payload = (html_content + js_content).lower()

        if not results["final_url"].startswith('https'):
            results["points"] += 45
            results["violations"].append({"name": "Unencrypted Connection", "desc": "الموقع يفتقر لتشفير SSL."})

        for threat, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, full_payload):
                results["points"] += 25
                results["violations"].append({"name": f"Suspicious {threat}", "desc": f"تم رصد كود يحاول الوصول إلى ({threat})."})

        domain = urlparse(results["final_url"]).netloc.lower()
        brands = ['google', 'facebook', 'paypal', 'bank', 'secure']
        for b in brands:
            if b in domain and not is_trusted(results["final_url"]):
                results["points"] += 60
                results["violations"].append({"name": "Brand Impersonation", "desc": f"اشتباه في محاولة تقليد العلامة التجارية '{b}'."})

    except Exception as e:
        results["risk_score"] = "Unknown"
        results["violations"].append({"name": "Scan Blocked", "desc": "الموقع يحظر أدوات التحليل أو غير متاح حالياً."})

    score = min(results["points"], 100)
    results["points"] = score
    if score >= 80: results["risk_score"] = "Critical"
    elif score >= 50: results["risk_score"] = "High"
    elif score >= 25: results["risk_score"] = "Medium"
    else: results["risk_score"] = "Low"

    results["analysis_time"] = round(time.time() - start_time, 2)
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"error": "رابط غير صالح"}), 400
    
    return jsonify(perform_deep_scan(url))

if __name__ == '__main__':
    app.run(debug=True)

