import os, re, requests, time
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from threading import Thread

app = Flask(__name__)

# بيانات المطور: طارق مصطفى
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# --- [ مسارات ملفات SEO والـ PWA من داخل مجلد static ] ---

@app.route('/robots.txt')
def static_from_root_robots():
    return send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
def static_from_root_sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/manifest.json')
def static_from_root_manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def static_from_root_sw():
    return send_from_directory('static', 'sw.js')

# --- [ محرك الذكاء الأمني المتقدم ] ---
BLACKLIST_DB = set()
WHITELIST = {'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'github.com'}

def sync_engine():
    global BLACKLIST_DB
    while True:
        try:
            new_db = set()
            sources = ["https://openphish.com/feed.txt"]
            for s in sources:
                r = requests.get(s, timeout=15)
                if r.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', r.text)
                    new_db.update([d.lower() for d in domains])
            BLACKLIST_DB = new_db
        except: pass
        time.sleep(3600)

Thread(target=sync_engine, daemon=True).start()

@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, violations = 0, []
    domain = urlparse(url).netloc.lower().replace('www.', '')

    try:
        if any(w in domain for w in WHITELIST):
            score, violations = 0, [{"name": "Trusted Authority", "desc": "النطاق مسجل ضمن المؤسسات الموثوقة عالمياً."}]
        elif domain in BLACKLIST_DB:
            score, violations = 100, [{"name": "Malicious Host", "desc": "تم رصد النطاق في قوائم التهديدات النشطة (Phishing Database)."}]
        else:
            res = requests.get(url, timeout=8, headers={"User-Agent": "SecuCode-Sentry-2026"}, verify=False)
            html = res.text
            if re.search(r'getUserMedia|mediaDevices|camera|microphone', html, re.I):
                score = 98
                violations.append({"name": "Spyware Pattern", "desc": "تم رصد أكواد تحاول الوصول للكاميرا أو الميكروفون بشكل مريب."})
            if not violations:
                violations = [{"name": "Clean Logic", "desc": "تحليل السلوك البرمجي لم يظهر أي أنشطة عدوانية حالياً."}]
    except:
        score, violations = 45, [{"name": "Analysis Shield", "desc": "الموقع يمنع الفحص الآلي، نوصي بالحذر عند التعامل معه."}]

    # إرسال إشعار تليجرام لطارق
    try:
        status = "🛑 CRITICAL" if score >= 80 else "🛡️ SAFE"
        msg = f"🔍 [SCAN] SecuCode Pro\n🌐 Host: {domain}\n📊 Risk: {score}%\n⚠️ Status: {status}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({
        "risk_score": "Critical" if score >= 80 else "Safe", 
        "points": score, 
        "violations": violations,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(debug=True)
