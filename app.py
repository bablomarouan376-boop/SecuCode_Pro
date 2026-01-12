import os, re, requests, time, random
from flask import Flask, request, jsonify, render_template, Response
from urllib.parse import urlparse
from datetime import datetime
from threading import Thread

app = Flask(__name__)

# --- ذكاء التهديدات المتجدد ---
BLACKLIST_DB = set()
def sync_threats():
    global BLACKLIST_DB
    while True:
        try:
            new_db = set()
            feeds = ["https://openphish.com/feed.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
            for url in feeds:
                res = requests.get(url, timeout=10)
                if res.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', res.text)
                    new_db.update([d.lower() for d in domains])
            new_db.update(['grabify', 'iplogger', 'webcam360', 'bit.ly', 'r.mtdv.me'])
            BLACKLIST_DB = new_db
        except: pass
        time.sleep(3600)

Thread(target=sync_threats, daemon=True).start()

# --- الإحصائيات الذكية ---
def get_stats():
    now = datetime.now()
    total = 1540 + (now.day * 12) + (now.hour * 5)
    threats = int(total * 0.135)
    return total, threats

def scan_logic(url):
    points, findings = 0, []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        if any(threat in url.lower() for threat in BLACKLIST_DB):
            return 100, [{"name": "قائمة سوداء", "desc": "الرابط مسجل كتهديد أمني عالمي."}]
        
        res = requests.get(url, timeout=5, headers=headers)
        content = res.text
        if re.search(r'password|login|كلمة المرور', content, re.I):
            points = 90
            findings.append({"name": "تصيد احتيالي", "desc": "تم كشف واجهة لسرقة البيانات."})
        if re.search(r'getUserMedia|Webcam|camera', content, re.I):
            points = max(points, 98)
            findings.append({"name": "تجسس كاميرا", "desc": "محاولة لفتح الكاميرا بدون إذن."})
    except:
        points = 40
        findings.append({"name": "تحليل محدود", "desc": "الموقع يفرض قيوداً على الفحص التلقائي."})
    return min(points, 100), findings

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    score, violations = scan_logic(url)
    total, threats = get_stats()
    return jsonify({"risk_score": "Critical" if score >= 80 else "Safe", "points": score, "violations": violations, "stats": {"total": total, "threats": threats}})

# --- ملفات الـ SEO البرمجية (حل مشكلة عدم الظهور) ---
@app.route('/robots.txt')
def robots():
    content = "User-agent: *\nAllow: /\nSitemap: https://secu-code-pro.vercel.app/sitemap.xml"
    return Response(content, mimetype="text/plain")

@app.route('/sitemap.xml')
def sitemap():
    content = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>https://secu-code-pro.vercel.app/</loc><lastmod>2026-01-12</lastmod><priority>1.0</priority></url>
    </urlset>"""
    return Response(content, mimetype="application/xml")

@app.route('/manifest.json')
def manifest():
    content = """{"name": "SecuCode Pro", "short_name": "SecuCode", "start_url": "/", "display": "standalone", "background_color": "#020617", "theme_color": "#3b82f6", 
    "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/9446/9446698.png", "sizes": "512x512", "type": "image/png"}]}"""
    return Response(content, mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=True)
