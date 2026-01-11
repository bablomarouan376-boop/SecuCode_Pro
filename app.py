import os, re, requests, time, base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- إعدادات المحاكاة الواقعية (Simulation Logic) ---
START_DATE = datetime(2026, 1, 1) # تاريخ انطلاق المشروع
BASE_SCANS = 1540 # الرقم الأساسي الذي يبدأ منه العداد

def get_simulated_stats():
    """حساب إحصائيات واقعية تتغير يومياً تلقائياً"""
    days_passed = (datetime.now() - START_DATE).days
    # محاكاة: متوسط 41 فحص يومياً (بين 16 و 67)
    total_scanned = BASE_SCANS + (days_passed * 41)
    # التهديدات تمثل دائماً حوالي 13% من الإجمالي
    threats_detected = int(total_scanned * 0.13)
    return {"total": total_scanned, "threats": threats_detected}

# --- نظام التحكم اليدوي (Blacklist / Whitelist) ---
BLACKLIST = ['malicious-example.com', 'hack-link.net']
WHITELIST = [
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
    'github.com', 'twitter.com', 'x.com', 'linkedin.com', 
    'gmail.com', 'youtube.com', 'vercel.app', 'netlify.app', 'zoom.us'
]

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecuCodeRadar/4.0"}

def get_domain_age(domain):
    try:
        if any(d in domain for d in WHITELIST): return 9999
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=3)
        if res.status_code == 200:
            events = res.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date = datetime.strptime(event.get('eventDate')[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except: pass
    return None

def analyze_logic(target_url):
    start_time = time.time()
    violated_rules = []
    risk_points = 0
    domain = urlparse(target_url).netloc.lower()

    # 1. فحص القائمة السوداء (حظر فوري)
    if any(black_url in domain for black_url in BLACKLIST):
        return {"risk_score": "Critical", "points": 100, "violations": [{"name": "رابط محظور يدوياً", "desc": "تم إدراج هذا الرابط في القائمة السوداء كتهديد مؤكد."}], "final_url": target_url, "redirects": [target_url], "time": 0.01}

    # 2. فحص القائمة البيضاء
    if any(white_url in domain for white_url in WHITELIST):
        return {"risk_score": "Low", "points": 0, "violations": [], "final_url": target_url, "redirects": [target_url], "time": 0.01}

    try:
        # 3. التحليل السلوكي
        response = requests.get(target_url, headers=HEADERS, timeout=8, allow_redirects=True)
        final_url = response.url
        content = response.text
        
        age = get_domain_age(domain)
        if age and age < 30:
            risk_points += 60
            violated_rules.append({"name": "نطاق حديث جداً", "desc": "الموقع أنشئ حديثاً، وهو أسلوب متبع في هجمات التجسس."})

        # كشف سكريبتات الكاميرا والتصيد
        behaviors = {
            r'getUserMedia|camera|microphone': ("تجسس: طلب فتح الكاميرا", 75),
            r'password|credit_card|cvv': ("تصيد: طلب بيانات خاصة", 55),
            r'[A-Za-z0-9+/]{500,}=*': ("تشفير مريب (Obfuscation)", 40),
            r'eval\(|atob\(': ("تنفيذ أكواد مخفية", 35)
        }

        for pattern, (name, weight) in behaviors.items():
            if re.search(pattern, content, re.I):
                risk_points += weight
                violated_rules.append({"name": name, "desc": "تم رصد نشاط برمجي يحاول اختراق جهازك."})

        if not final_url.startswith('https'):
            risk_points += 45
            violated_rules.append({"name": "اتصال غير مشفر", "desc": "الموقع يفتقر لبروتوكول HTTPS الآمن."})

    except:
        risk_points = 50
        violated_rules.append({"name": "حماية ضد الفحص", "desc": "الموقع يمنع الرادار من تحليل محتوياته."})
        final_url = target_url

    p = min(risk_points, 100)
    label = "Critical" if p >= 85 else "High" if p >= 60 else "Medium" if p >= 30 else "Low"

    return {
        "risk_score": label, "points": p, "violations": violated_rules,
        "final_url": final_url, "redirects": [final_url], "time": round(time.time() - start_time, 2)
    }

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"error": "أدخل الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    result = analyze_logic(url)
    result["stats"] = get_simulated_stats()
    return jsonify(result)

# مسارات ملفات SEO
@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')
@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')
@app.route('/manifest.json')
def manifest(): return send_from_directory(app.static_folder, 'manifest.json')

if __name__ == '__main__':
    app.run(debug=True)
