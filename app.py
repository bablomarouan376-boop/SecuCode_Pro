import os
import re
import requests
import socket
import ssl
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

# إعداد التطبيق
app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات متصفح احترافية لتجاوز جدران الحماية (Stealth Mode)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
    "Referer": "https://www.google.com/"
}

def get_domain_age(domain):
    """فحص عمر النطاق عبر بروتوكول RDAP لكشف المواقع الحديثة جداً"""
    try:
        if not domain or '.' not in domain or len(domain) < 3:
            return None
        # جلب بيانات التسجيل عالمياً
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            events = data.get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date_str = event.get('eventDate')
                    reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except:
        pass
    return None

def deobfuscate_hidden_logic(content):
    """فك تشفير النصوص المخفية (Base64) لكشف الأكواد المضللة"""
    extracted_logic = ""
    # البحث عن نصوص Base64 المحتملة في الكود
    potential_b64 = re.findall(r'["\']([A-Za-z0-9+/]{35,})={0,2}["\']', content)
    for b in potential_b64:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            extracted_logic += " " + decoded
        except:
            continue
    return extracted_logic

def fetch_and_scan_js(html, base_url):
    """مطاردة ملفات الـ JavaScript الخارجية وفحص محتواها"""
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    js_payload = ""
    for s in scripts[:4]: # فحص أول 4 ملفات لضمان التغطية والسرعة
        try:
            full_url = urljoin(base_url, s)
            r = requests.get(full_url, headers=HEADERS, timeout=4)
            js_payload += "\n" + r.text
        except:
            continue
    return js_payload

def perform_ultimate_analysis(target_url):
    """المحرك الرئيسي لتحليل التهديدات الشامل لبرنامج SecuCode Pro"""
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    risk_points = 0
    
    try:
        session = requests.Session()
        # تتبع مسار التحويلات بالكامل
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = response.url
        main_html = response.text
        
        # تجميع المحتوى للفحص (HTML + JS خارجي + محتوى مفكوك التشفير)
        extended_js = fetch_and_scan_js(main_html, final_url)
        full_content = main_html + extended_js
        full_content += deobfuscate_hidden_logic(full_content)

        # 1. تحليل عمر النطاق (Domain Intelligence)
        domain = urlparse(final_url).netloc
        age = get_domain_age(domain)
        if age is not None:
            if age < 31:
                risk_points += 55
                violated_rules.append({"name": "نطاق حديث جداً (خطر عالي)", "risk_description": f"تم إنشاء هذا الموقع منذ {age} يوم فقط. المواقع الجديدة غالباً ما تُستخدم في حملات التصيد السريع.", "points_added": 55})
            elif age < 180:
                risk_points += 25
                violated_rules.append({"name": "نطاق غير مستقر", "risk_description": "عمر الموقع أقل من 6 أشهر، مما يجعله تحت مجهر المراجعة الأمنية.", "points_added": 25})

        # 2. كشف الأذونات والخصوصية (Permissions Tracker)
        threat_patterns = {
            'Camera/Microphone': r'getUserMedia|mediaDevices|camera|video|microphone|record|stream',
            'Location/GPS': r'getCurrentPosition|watchPosition|geolocation',
            'Data Exfiltration': r'canvas\.toDataURL|atob\(|btoa\(|upload|POST|fetch|XMLHttpRequest|base64',
            'Phishing Forms': r'password|credit_card|cvv|exp_month|ssn|social_security|pin_code|billing'
        }

        for category, pattern in threat_patterns.items():
            if re.search(pattern, full_content, re.I):
                weight = 75 if 'Camera' in category or 'Phishing' in category else 40
                risk_points += weight
                violated_rules.append({
                    "name": f"نشاط مشبوه: {category}", 
                    "risk_description": f"تم رصد محاولة برمجية للوصول إلى ({category}) أو سحب بيانات حساسة فور الدخول.", 
                    "points_added": weight
                })

        # 3. تحليل الروابط والتحويلات
        if len(response.history) > 2:
            risk_points += 30
            violated_rules.append({"name": "سلسلة تحويلات مريبة", "risk_description": f"الرابط قام بالتحويل {len(response.history)} مرات لإخفاء الوجهة النهائية.", "points_added": 30})
        
        for r in response.history:
            if r.url not in redirect_path: redirect_path.append(r.url)
        if final_url not in redirect_path: redirect_path.append(final_url)

        # كشف انتحال العلامات التجارية
        brands = ['facebook', 'google', 'paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'binance', 'instagram']
        for b in brands:
            if b in domain.lower() and domain.lower() != f"{b}.com":
                risk_points += 45
                violated_rules.append({"name": "اشتباه انتحال علامة تجارية", "risk_description": f"الموقع يستخدم اسم '{b}' في الرابط لخداع المستخدمين بأنه الموقع الرسمي.", "points_added": 45})

        if not final_url.startswith('https'):
            risk_points += 50
            violated_rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع لا يستخدم بروتوكول HTTPS، مما يعرض خصوصيتك للخطر.", "points_added": 50})

    except Exception:
        risk_points += 35
        violated_rules.append({"name": "نظام حماية ضد الفحص", "risk_description": "الموقع يحظر أدوات الرادار، وهو مؤشر خطر عالي يُستخدم عادةً لإخفاء البرمجيات الضارة.", "points_added": 35})
        final_url = target_url

    # النتيجة النهائية وتصنيف الخطر
    final_score = min(risk_points, 100)
    risk_label = "Critical" if final_score >= 80 else "High" if final_score >= 50 else "Medium" if final_score >= 25 else "Low"

    return {
        "risk_score": risk_label,
        "suspicious_points": final_score,
        "violated_rules": violated_rules,
        "link_final": final_url,
        "redirect_path": redirect_path,
        "execution_time": round(time.time() - start_time, 2)
    }

# مسارات التطبيق (Routes)
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"message": "يرجى إدخال الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "الرابط غير صالح"}), 400
    return jsonify(perform_ultimate_analysis(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)

