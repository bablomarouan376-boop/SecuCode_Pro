from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS 
import whois
from datetime import datetime

app = Flask(__name__)
CORS(app) 

# --- وظيفة فحص سمعة IP (القاعدة 7) ---
def check_ip_reputation(domain):
    reputation_points = 0
    try:
        api_url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
        response = requests.get(api_url, timeout=3)
        host_count = len(response.text.split('\n'))
        if host_count > 10:
            reputation_points += 2
    except Exception:
        reputation_points += 0 
    return reputation_points

# --- وظيفة تحليل الرابط الرئيسية (7 قواعد) ---
def analyze_url(url):
    points = 0
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
    except ValueError:
        return 10 

    # القواعد 1-5 (هيكلية الرابط)
    if len(url) > 70: points += 1
    
    suspicious_keywords = ['login', 'verify', 'update', 'security', 'account', 'paypal', 'bank']
    for keyword in suspicious_keywords:
        if keyword in domain:
            points += 2
            break
            
    if parsed_url.scheme == 'http': points += 3
    if '@' in url: points += 5
    if domain.count('.') > 3: points += 1

    # القاعدة 6: فحص عُمر النطاق (Whois)
    try:
        w = whois.whois(domain)
        today = datetime.now().date()
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age_in_days = (today - creation_date.date()).days
            if age_in_days < 90: points += 4 
            elif age_in_days < 180: points += 2 
    except Exception: 
        points += 1 
    
    # القاعدة 7: فحص سمعة IP
    points += check_ip_reputation(domain)

    # تحليل المحتوى البسيط
    try:
        response = requests.get(url, timeout=5) 
        response.raise_for_status() 
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else ""
        if not title or len(title.strip()) < 5:
            points += 1
    except requests.exceptions.RequestException:
        points += 1
    except Exception:
        points += 1 

    return points

# واجهة الـ API
@app.route('/check_link', methods=['POST'])
def check_link():
    data = request.get_json()
    link = data.get('link')

    if not link:
        return jsonify({"error": "الرجاء إرسال حقل 'link' في صيغة JSON"}), 400

    score = analyze_url(link)
    
    if score >= 6:
        result = "🔴 احتيالي/مشتبه به جداً"
        certainty = "High"
    elif score >= 3:
        result = "🟡 مشتبه به"
        certainty = "Medium"
    else:
        result = "🟢 آمن نسبياً"
        certainty = "Low"

    return jsonify({"link": link,"score": score,"certainty": certainty,"result": result})

if __name__ == '__main__':
    print("تشغيل API SecuCode...")
    app.run(host='0.0.0.0', port=5000, debug=True)
