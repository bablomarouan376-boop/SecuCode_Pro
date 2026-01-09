import os
import re
import requests
import time
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

# قائمة المواقع الموثوقة التي لا تخضع للفحص الصارم (White List)
TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com', 
    'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 
    'github.com', 'youtube.com', 'vercel.app', 'openai.com'
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

def analyze_logic(url):
    """تحليل ذكي يفرق بين الأكواد الطبيعية والتهديدات الحقيقية"""
    start_time = time.time()
    violated_rules = []
    risk_points = 0
    domain = urlparse(url).netloc.lower().replace('www.', '')

    # 1. إذا كان الموقع في القائمة البيضاء، فهو آمن بنسبة 99%
    is_trusted = any(trusted in domain for trusted in TRUSTED_DOMAINS)
    
    try:
        session = requests.Session()
        # تتبع التحويلات
        response = session.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        content = response.text.lower()

        if is_trusted:
            return {
                "risk_score": "Low",
                "suspicious_points": 5,
                "violated_rules": [],
                "final_url": final_url,
                "message": "هذا الموقع ينتمي لمؤسسة موثوقة ومعروفة عالمياً."
            }

        # 2. فحص التشفير (HTTPS)
        if not final_url.startswith('https'):
            risk_points += 30
            violated_rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع لا يستخدم بروتوكول HTTPS، مما قد يعرض بياناتك للتنصت."})

        # 3. فحص التهديدات الحقيقية (بدون مبالغة)
        # بدلاً من البحث عن الكاميرا فقط، نبحث عن "أدوات التجسس المخفية"
        heavy_threats = {
            'محاولة تسجيل نقرات المفاتيح': r'onkeydown|onkeypress|keycode|keylog',
            'سكربتات تعدين العملات (CoinHive)': r'coinhive\.min\.js|cryptonight|minero',
            'روابط تصيد (Phishing)': r'login-verification|secure-update|account-confirm'
        }

        for name, pattern in heavy_threats.items():
            if re.search(pattern, content):
                risk_points += 40
                violated_rules.append({"name": name, "risk_description": "تم رصد نمط برمجي يشبه السلوك المستخدم في المواقع الاحتيالية."})

        # 4. تتبع التحويلات المريبة
        if len(response.history) > 3:
            risk_points += 20
            violated_rules.append({"name": "قفزات تحويل متعددة", "risk_description": "الرابط يحولك بين أكثر من 3 مواقع، وهذا أسلوب متبع لإخفاء الوجهة النهائية."})

    except Exception as e:
        return {
            "risk_score": "Unknown",
            "suspicious_points": 0,
            "violated_rules": [{"name": "الموقع لا يستجيب", "risk_description": "تعذر الاتصال بالرابط، ربما يكون الموقع معطلاً أو يحظر أدوات الفحص."}],
            "final_url": url
        }

    # تصنيف الخطر بناءً على نقاط حقيقية
    score = min(risk_points, 100)
    label = "Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 30 else "Low"

    return {
        "risk_score": label,
        "suspicious_points": score,
        "violated_rules": violated_rules,
        "final_url": final_url,
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"message": "يرجى إدخال الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "الرابط غير صالح"}), 400
    return jsonify(analyze_logic(url))

if __name__ == '__main__':
    app.run(debug=True)

