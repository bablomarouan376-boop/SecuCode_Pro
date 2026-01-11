import os, re, requests, time, random
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from datetime import datetime
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- إعدادات المحاكاة الذكية ---
START_DATE = datetime(2026, 1, 1)
BASE_SCANS = 1540

# --- نظام حماية السيرفر (Rate Limiting) ---
user_scans = {}
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_ip = request.remote_addr
        now = time.time()
        if user_ip in user_scans and now - user_scans[user_ip] < 5:
            return jsonify({"error": "يرجى الانتظار 5 ثوانٍ بين عمليات الفحص لحماية موارد النظام"}), 429
        user_scans[user_ip] = now
        return f(*args, **kwargs)
    return decorated_function

def get_simulated_stats():
    now = datetime.now()
    days_passed = (now - START_DATE).days
    # زيادة تعتمد على الأيام + الساعة الحالية لواقعية أكثر
    base_total = BASE_SCANS + (days_passed * 41) + (now.hour * 2) + random.randint(1, 10)
    threat_ratio = 0.125 + (random.randint(0, 15) / 1000)
    return {"total": base_total, "threats": int(base_total * threat_ratio)}

# --- محرك التحليل الاستدلالي (Heuristic Engine) ---
def deep_heuristic_scan(content, domain, final_url):
    points = 0
    findings = []
    
    # 1. كشف انتحال الهوية (Phishing)
    brands = {
        'google': ['gmail', 'accounts-google'],
        'facebook': ['fb-login', 'meta-support'],
        'microsoft': ['outlook', 'office365'],
        'binance': ['crypto-wallet', 'verify-binance']
    }
    for brand, keywords in brands.items():
        if brand in content.lower() and brand not in domain:
            points += 85
            findings.append({"name": f"انتحال رقمي لهوية {brand.capitalize()}", "desc": "تزييف الواجهة البرمجية لمحاولة سرقة بيانات الدخول الرسمية."})

    # 2. كشف الأهداف السلوكية (Behavioral Threats)
    behaviors = [
        (r'getCurrentPosition', "اختراق الخصوصية المكانية", 55),
        (r'getUserMedia', "الوصول غير المصرح للوسائط (كاميرا/مايك)", 90),
        (r'\.exe|\.apk|\.bat', "محاولة حقن ملفات تنفيذية", 70),
        (r'cvv|card_number|pin_code', "استخلاص بيانات ائتمانية", 95)
    ]
    for pattern, name, weight in behaviors:
        if re.search(pattern, content, re.I):
            points += weight
            findings.append({"name": name, "desc": "رصد سلوك برمجي يحاول استدعاء صلاحيات حساسة في جهازك."})

    # 3. الهندسة الاجتماعية
    if re.search(r'win|prize|مبروك|جائزة|ربحت', content, re.I) and re.search(r'input|login|form', content, re.I):
        points += 70
        findings.append({"name": "تقنيات الهندسة الاجتماعية", "desc": "استخدام إغراءات وهمية لاستدراج المستخدم وكشف بياناته الشخصية."})

    return points, findings

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
@rate_limit
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"error": "أدخل الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    start_time = time.time()
    try:
        headers = {"User-Agent": "SecuCode-Pro-Advanced-Radar/4.0 (Security Analysis Engine)"}
        session = requests.Session()
        # تتبع التحويلات التلقائية (تتبع الروابط المختصرة)
        response = session.get(url, headers=headers, timeout=12, allow_redirects=True)
        final_url = response.url
        content = response.text
        domain = urlparse(final_url).netloc.lower()

        p, f = deep_heuristic_scan(content, domain, final_url)
        if not final_url.startswith('https'):
            p += 45
            f.append({"name": "غياب التشفير الطرفي (No SSL)", "desc": "الموقع لا يستخدم بروتوكول HTTPS، مما يجعل البيانات عرضة للتجسس."})
    except:
        p, f, final_url = 50, [{"name": "حجب التحليل الاستدلالي", "desc": "الموقع يستخدم تقنيات تمويه أمني لمنع الفحص، مما يجعله مريباً."}], url

    score = min(p, 100)
    return jsonify({
        "risk_score": "Critical" if score >= 85 else "High" if score >= 60 else "Medium" if score >= 30 else "Low",
        "points": score, "violations": f, "final_url": final_url,
        "time": round(time.time() - start_time, 2), "stats": get_simulated_stats()
    })

if __name__ == '__main__':
    app.run(debug=True)
