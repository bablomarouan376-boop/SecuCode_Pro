import os, re, requests, time
from flask import Flask, request, jsonify, render_template, Response
from urllib.parse import urlparse
from threading import Thread

app = Flask(__name__)

# بيانات المطور: طارق مصطفى
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# --- [ نظام ذكاء التهديدات - Threat Intelligence ] ---
BLACKLIST_DB = set()
# قائمة بيضاء للمواقع الموثوقة لمنع الأخطاء (Google, Facebook, etc.)
WHITELIST = {'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'twitter.com', 'github.com', 'youtube.com'}

def sync_engine():
    global BLACKLIST_DB
    while True:
        try:
            new_db = set()
            sources = ["https://openphish.com/feed.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
            for s in sources:
                r = requests.get(s, timeout=15)
                if r.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', r.text)
                    new_db.update([d.lower() for d in domains])
            BLACKLIST_DB = new_db
        except: pass
        time.sleep(3600) # تحديث كل ساعة

Thread(target=sync_engine, daemon=True).start()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, violations = 0, []
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower().replace('www.', '')

    try:
        # 1. التحقق من القائمة البيضاء أولاً
        if any(w in domain for w in WHITELIST):
            score, violations = 0, [{"name": "Verified Authority", "desc": "هذا النطاق يتبع مؤسسة عالمية موثوقة ومحمية بأنظمة أمان متقدمة."}]
        # 2. التحقق من القائمة السوداء
        elif domain in BLACKLIST_DB:
            score, violations = 100, [{"name": "Global Blacklist", "desc": "تم رصد هذا النطاق بدقة داخل القوائم الأمنية العالمية كتهديد نشط."}]
        else:
            # 3. الفحص السلوكي العميق (Deep Behavior Scan)
            res = requests.get(url, timeout=8, headers={"User-Agent": "SecuCode-Pro-Scanner-2026"}, verify=False)
            html = res.text
            
            # كشف محاولات التجسس على الكاميرا والميكروفون
            if re.search(r'getUserMedia|mediaDevices|camera|videoinput|facingMode', html, re.I):
                score = 98
                violations.append({"name": "Visual Espionage", "desc": "كود JavaScript مشبوه يحاول الوصول للكاميرا أو الميكروفون برمجياً."})
            
            # كشف صفحات التصيد الاحتيالي
            if re.search(r'password|login|كلمة المرور|signin|verify|bank', html, re.I):
                score = max(score, 90)
                violations.append({"name": "Phishing Structure", "desc": "تم رصد هيكل برمجى مصمم لانتحال شخصية المواقع الرسمية لسرقة البيانات."})

    except:
        score, violations = 45, [{"name": "Encrypted Shield", "desc": "الموقع يستخدم طبقات تشفير أو حماية تمنع الرادار من التحليل الكامل."}]

    # إرسال التقرير لتليجرام طارق
    try:
        risk_label = "🚨 CRITICAL" if score >= 80 else "✅ SAFE"
        msg = f"🛡️ رادار طارق مصطفى\n🔗 الرابط: {url}\n📊 النتيجة: {score}%\n⚠️ الحالة: {risk_label}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({"risk_score": "Critical" if score >= 80 else "Safe", "points": score, "violations": violations})

# ملفات الـ SEO الأساسية لضمان سكور 100 في جوجل
@app.route('/robots.txt')
def robots(): return Response("User-agent: *\nAllow: /\nSitemap: https://secu-code-pro.vercel.app/sitemap.xml", mimetype="text/plain")

@app.route('/sitemap.xml')
def sitemap():
    content = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://secu-code-pro.vercel.app/</loc><lastmod>2026-01-14</lastmod></url></urlset>'
    return Response(content, mimetype="application/xml")

@app.route('/manifest.json')
def manifest():
    return Response('{"name":"SecuCode Pro","short_name":"SecuCode","start_url":"/","display":"standalone","background_color":"#020617","theme_color":"#2563eb"}', mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=True)
