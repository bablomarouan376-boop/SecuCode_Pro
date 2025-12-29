import os
import re
import requests
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from validators import url

app = Flask(__name__)

# إعدادات الاتصال الاحترافية
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
}

def check_ssl_status(hostname):
    """فحص قوة وجودة شهادة SSL"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True, "شهادة صالحة وموثوقة"
    except Exception as e:
        return False, str(e)

def perform_deep_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    points = 0
    
    parsed = urlparse(target_url)
    domain = parsed.netloc

    # --- 1. فحص الهيكل (Static Analysis) ---
    static_rules = [
        (r'@', 50, "استخدام رمز @", "يستخدم لتوجيه المستخدم لموقع مخفي خلف اسم مستخدم وهمي."),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 60, "عنوان IP مباشر", "المواقع الموثوقة تستخدم أسماء نطاقات وليس أرقام IP مباشرة."),
        (r'-{2,}', 20, "شرطات مكررة في الرابط", "غالباً ما تستخدم في روابط التصيد لتقليد علامات تجارية."),
        (r'(login|verify|update|secure|bank|paypal|account)', 30, "كلمات حساسة في الرابط", "محاولة إيهام المستخدم بأن الصفحة رسمية وحساسة."),
        (r'\.zip$|\.exe$|\.rar$|\.apk$', 80, "ملف تنفيذي/مضغوط مباشر", "الرابط يقوم بتحميل ملفات قد تحتوي على برمجيات خبيثة.")
    ]

    for pattern, pts, name, desc in static_rules:
        if re.search(pattern, target_url, re.I):
            points += pts
            violated_rules.append({"name": name, "risk_description": desc, "points_added": pts})

    # --- 2. فحص الاتصال (Dynamic Analysis) ---
    try:
        response = requests.get(target_url, headers=HEADERS, timeout=8, allow_redirects=True)
        final_url = response.url
        content = response.text
        
        # فحص HTTPS
        if not final_url.startswith('https'):
            points += 40
            violated_rules.append({"name": "اتصال غير مشفر HTTP", "risk_description": "الموقع لا يستخدم تشفير SSL، مما يجعل بياناتك عرضة للسرقة.", "points_added": 40})
        else:
            is_valid, msg = check_ssl_status(urlparse(final_url).netloc)
            if not is_valid:
                points += 30
                violated_rules.append({"name": "مشكلة في شهادة SSL", "risk_description": "شهادة الأمان غير صالحة أو غير موثوقة.", "points_added": 30})

        # فحص محتوى الصفحة (Phishing Detect)
        if re.search(r'<input[^>]*type="password"', content, re.I):
            if points > 20: # إذا كان هناك شك مسبق
                points += 50
                violated_rules.append({"name": "نموذج طلب كلمة مرور", "risk_description": "تم العثور على حقل إدخال باسورد في صفحة مشبوهة.", "points_added": 50})

    except Exception:
        points += 30
        violated_rules.append({"name": "فشل فحص الاستجابة", "risk_description": "الموقع لا يستجيب بشكل طبيعي أو يحظر أدوات الفحص.", "points_added": 30})
        final_url = target_url

    # --- 3. تصنيف النتيجة ---
    if points >= 80: risk = "Critical"
    elif points >= 45: risk = "High"
    elif points >= 20: risk = "Medium"
    else: risk = "Low"

    return {
        "risk_score": risk,
        "suspicious_points": points,
        "violated_rules": violated_rules,
        "link_final": final_url,
        "detected_warnings": len(violated_rules),
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('link', '').strip()
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url
    
    result = perform_deep_analysis(raw_url)
    result["link_input"] = raw_url
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
