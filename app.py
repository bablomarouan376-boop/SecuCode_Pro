import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin

app = Flask(__name__, static_folder='static', template_folder='templates')

# تحديث الـ HEADERS لتبدو كمتصفح حقيقي وتجنب الحظر
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
}

def deep_scanner(html, url):
    """تحسين الفحص العميق ليكون أدق وأسرع"""
    intel = html
    try:
        scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
        for s in scripts[:3]: # تقليل العدد لـ 3 لسرعة الاستجابة على Vercel
            try:
                full_s_url = urljoin(url, s)
                # تجنب فحص مكتبات موثوقة مثل tailwind أو lucide لتقليل الخطأ
                if any(x in full_s_url for x in ['tailwindcss', 'lucide', 'google-analytics']):
                    continue
                r = requests.get(full_s_url, headers=HEADERS, timeout=3)
                intel += "\n" + r.text
            except: continue
        
        # فك تشفير Base64 (فقط إذا كان النص يبدو ككود برمجى)
        potential_b64 = re.findall(r'["\']([A-Za-z0-9+/]{40,})={0,2}["\']', intel)
        for b in potential_b64:
            try:
                decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
                if any(k in decoded.lower() for k in ['http', 'eval', 'getusermedia']):
                    intel += "\n" + decoded
            except: continue
    except: pass
    return intel

@app.route('/')
def home(): 
    return render_template('index.html')

# إضافة مسارات الـ Sitemap و Robots لضمان ظهور موقعك بشكل صحيح في جوجل
@app.route('/robots.txt')
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route('/analyze', methods=['POST'])
def analyze():
    target = request.json.get('link', '').strip()
    if not target: return jsonify({"message": "فارغ"}), 400
    
    # تحسين التعامل مع الروابط
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    start = time.time()
    path = [target]
    risk = 0
    rules = []

    try:
        session = requests.Session()
        # محاكاة تتبع التحويلات بشكل آمن
        res = session.get(target, headers=HEADERS, timeout=10, allow_redirects=True)
        
        for r in res.history:
            if r.url not in path: path.append(r.url)
        if res.url not in path: path.append(res.url)
        
        final_url = res.url
        domain = urlparse(final_url).netloc.lower()
        
        full_intel = deep_scanner(res.text, final_url)
        
        # 1. تحسين فحص الكاميرا (البحث عن الكود الكامل لمنع الخطأ مع جوجل)
        # تم تغيير 'camera' لـ 'navigator.mediaDevices' لتجنب كشف الكلمات العادية
        camera_pattern = r'navigator\.mediaDevices\.getUserMedia|mediaDevices\.getUserMedia'
        if re.search(camera_pattern, full_intel, re.I):
            risk += 85
            rules.append({"name": "تجسس: الوصول للكاميرا", "risk_description": "تم رصد محاولة برمجية لفتح الكاميرا أو المايكروفون."})

        # 2. تحسين فحص الماركات (إصلاح مشكلة جوجل Safe)
        brands = {'google': 'google.com', 'facebook': 'facebook.com', 'paypal': 'paypal.com', 'instagram': 'instagram.com'}
        is_official = False
        for brand, official in brands.items():
            if brand in domain:
                if official in domain: # إذا كان النطاق الرسمي فعلاً
                    is_official = True
                    break
                else: # إذا كان ينتحل الاسم
                    risk += 90
                    rules.append({"name": "انتحال هوية", "risk_description": f"الموقع ينتحل اسم {brand} ولكنه ليس الرابط الرسمي."})

        # إذا كان الموقع هو جوجل الرسمي أو فيسبوك، نجعل الخطر صفر فوراً
        if is_official:
            risk = 0
            rules = []

        if risk > 0 and not final_url.startswith('https'):
            risk += 15
            rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع لا يستخدم بروتوكول HTTPS."})

    except Exception as e:
        risk = 10 # درجة منخفضة جداً عند فشل الاتصال
        final_url = target

    score_label = "Critical" if risk >= 75 else "High" if risk >= 40 else "Medium" if risk >= 20 else "Low"
    
    return jsonify({
        "risk_score": score_label,
        "suspicious_points": min(risk, 100),
        "violated_rules": rules,
        "redirect_path": path,
        "execution_time": round(time.time() - start, 2)
    })

if __name__ == '__main__':
    app.run(debug=True)
