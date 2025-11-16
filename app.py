import os
from flask import Flask, request, jsonify, render_template
import requests
import re 
from urllib.parse import urlparse
from validators import url

app = Flask(__name__)

# --- تعريف 35 قاعدة أمنية متقدمة ---
SECURITY_RULES = [
    # قواعد المخاطر الحرجة (Critical Risks)
    { "check": lambda link, content: content is not None and bool(re.search(r'<form[^>]*\b(password|user|credit|card|cvv|secure|login|pin)\b', content, re.IGNORECASE | re.DOTALL)), "name": "نموذج تصيد يطلب بيانات حساسة (Phishing Form)", "risk": "وجود نموذج إدخال يطلب كلمات مرور أو بيانات بنكية. **خطر حرج للغاية.**", "points": 100 },
    { "check": lambda link, content: link.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar')), "name": "الانتهاء بملف تنفيذي ضار", "risk": "الرابط سيقوم بتحميل أو تشغيل ملف تنفيذي مباشرة.", "points": 80 },
    { "check": lambda link, content: '@' in link, "name": "رمز @ في الرابط (Obfuscation)", "risk": "يستخدم لخداع المتصفح والزائر حول الوجهة الحقيقية.", "points": 40 },
    { "check": lambda link, content: 'data:' in link.lower() or 'javascript:' in link.lower(), "name": "استخدام أنظمة URI خطيرة (Data/JavaScript)", "risk": "يسمح بتشغيل كود JavaScript مباشرة.", "points": 35 },
    { "check": lambda link, content: link.lower().startswith('http://'), "name": "بروتوكول HTTP غير الآمن", "risk": "الرابط غير مشفر (غير HTTPS). **خطر حرج.**", "points": 35 },
    { "check": lambda link, content: 'xn--' in link.lower(), "name": "وجود Punycode/IDN (خداع الأحرف الدولية)", "risk": "انتحال شخصية موقع آخر باستخدام أحرف دولية.", "points": 35 },
    { "check": lambda link, content: content is not None and bool(re.search(r'document\.write|eval\(|unescape\(|setTimeout\([^,]*?\d{4,}', content, re.IGNORECASE)), "name": "كود JavaScript مُشفر أو تأخير خطير", "risk": "وجود دوال تُستخدم لتنفيذ كود ضار أو تأخير إعادة التوجيه.", "points": 30 },
    
    # قواعد خداع النطاقات (High Risks)
    { "check": lambda link, content: any(re.search(rf'{word}', link.lower()) for word in ['payp@l', 'apple-id', 'googl-e', 'micr0s0ft', 'secure-bank']), "name": "Typosquatting في الأسماء الكبرى", "risk": "انتحال شخصية المواقع الكبرى باستخدام أخطاء إملائية ذكية.", "points": 50 },
    { "check": lambda link, content: any(company in link.lower() for company in ['microsoft', 'apple', 'amazon', 'facebook']) and 'https' not in link.lower(), "name": "اسم شركة كبرى بدون تشفير HTTPS", "risk": "تزوير واضح يهدف للتصيد.", "points": 30 },
    { "check": lambda link, content: 'login' in link.lower() and urlparse(link).netloc.count('.') > 2, "name": "كلمة 'Login' في نطاق فرعي عميق", "risk": "محاولة للتخفي وانتحال صفحات الدخول.", "points": 25 },
    { "check": lambda link, content: any(ext in link.lower() for ext in ['.tk', '.ga', '.ml', '.xyz', '.cc', '.biz', '.top']), "name": "انتهاء نطاق مشبوه (TLD)", "risk": "امتدادات نطاقات شائعة الاستخدام في حملات التصيد.", "points": 12 },
    { "check": lambda link, content: bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(link).netloc)), "name": "استخدام رقم IP مباشر في النطاق", "risk": "يشير إلى خادم مؤقت أو غير مسجل رسمياً.", "points": 30 },
    { "check": lambda link, content: any(word in link.lower() for word in ['secure', 'safe', 'trust']) and 'https' not in link.lower(), "name": "كلمات أمان زائفة بدون تشفير", "risk": "إيهام المستخدم بالأمان (HTTP مع كلمة 'secure').", "points": 30 },
    
    # قواعد السلوك والتوجيه (Behavioral and Redirect Risks)
    { "check": lambda link, content: content is not None and bool(re.search(r'window\.location\.replace|meta\s*http-equiv\s*=\s*"refresh"', content, re.IGNORECASE)), "name": "كود إعادة توجيه متقدم (Client-Side Redirect)", "risk": "نقل المستخدم فوراً إلى رابط آخر باستخدام جافاسكريبت أو HTML.", "points": 15 },
    { "check": lambda link, content: any(param in urlparse(link).query for param in ['redir', 'forward', 'url', 'destination']), "name": "وجود متغيرات إعادة التوجيه (Open Redirect)", "risk": "قد تسمح بالاستغلال لتنفيذ عمليات إعادة توجيه مفتوحة.", "points": 10 },
    { "check": lambda link, content: link.count('.') > 4, "name": "كثرة النطاقات الفرعية العميقة (>4)", "risk": "تستخدم لتقليد المواقع الشرعية (خدعة بصرية).", "points": 18 },
    { "check": lambda link, content: link.count('http') > 1, "name": "تكرار البروتوكول داخل الرابط", "risk": "محاولة خداع متقدمة لتمرير البروتوكول داخل المسار.", "points": 15 },
    { "check": lambda link, content: content is not None and len(content) < 500, "name": "محتوى صفحة قصير جداً", "risk": "يشير إلى أن الصفحة فارغة أو أنها مجرد صفحة إعادة توجيه فورية مخفية.", "points": 15 },
    { "check": lambda link, content: content is not None and len(content) > 1000000, "name": "حجم محتوى مبالغ فيه", "risk": "قد يشير إلى محاولة إغراق المتصفح أو تجاوز حجم ذاكرة الخادم.", "points": 10 },

    # قواعد فحص المسار والملفات (Path and File Risks)
    { "check": lambda link, content: any(word in urlparse(link).path.lower() for word in ['admin', 'upload', 'config', 'backup', 'password']), "name": "كلمات إدارة وحساسة في المسار", "risk": "قد يشير إلى محاولة الوصول لصفحة إدارة.", "points": 10 },
    { "check": lambda link, content: bool(re.search(r'\.\./|\.\.\\|\.\.%2f|\.\.%5c', link, re.IGNORECASE)), "name": "مؤشر لـ Directory Traversal", "risk": "محاولة للوصول إلى ملفات خارج المسار المخصص على الخادم.", "points": 12 },
    { "check": lambda link, content: bool(re.search(r'\.(php|asp|jsp|cgi)$', urlparse(link).path, re.IGNORECASE)), "name": "انتهاء بملف سكريبت تنفيذي", "risk": "قد يشير إلى محاولة تنفيذ سكريبت على الخادم.", "points": 8 },
    { "check": lambda link, content: len(urlparse(link).path) > 100, "name": "طول مبالغ فيه للمسار (Path)", "risk": "مسارات طويلة جداً قد تستخدم للخداع أو حقن البيانات.", "points": 6 },

    # قواعد الخداع الاجتماعي والتسويق (Social Engineering Risks)
    { "check": lambda link, content: any(word in link.lower() for word in ['gift', 'prize', 'free', 'win', 'claim', 'crypto', 'wallet']), "name": "استخدام كلمات خداع اجتماعي شائعة", "risk": "يشير إلى محاولة خداع اجتماعي وإغراء.", "points": 8 },
    { "check": lambda link, content: link.count('free') > 1 or link.count('verify') > 1, "name": "تكرار كلمات الخداع (Free/Verify)", "risk": "الاستخدام المفرط لكلمات الإغراء والحاجة للتحقق.", "points": 9 },
    
    # قواعد متقدمة أخرى
    { "check": lambda link, content: content is not None and bool(re.search(r'onload|onerror', content, re.IGNORECASE)), "name": "استخدام Onload/Onerror في HTML", "risk": "يشير إلى محاولة تنفيذ كود خبيث عند تحميل العنصر.", "points": 15 },
    { "check": lambda link, content: len(urlparse(link).netloc.split('.')[0]) > 20, "name": "طول مبالغ فيه للنطاق الفرعي", "risk": "النطاقات الفرعية الطويلة جداً مؤشراً على الإزعاج أو الخداع.", "points": 6 },
    { "check": lambda link, content: link.count('=') > 7, "name": "كثرة المتغيرات في الرابط (>7)", "risk": "قد تكون محاولة لحقن أو تمرير معلمات ضخمة.", "points": 4 },
    { "check": lambda link, content: any(keyword in link.lower() for keyword in ['phishing', 'scam', 'malware', 'exploit']), "name": "كلمات أمنية ذاتية الإشارة", "risk": "الرابط يحتوي على كلمات تشير إلى أنه ضار بشكل مباشر.", "points": 20 },
    { "check": lambda link, content: content is not None and 'iframe' in content.lower() and urlparse(link).netloc not in content.lower(), "name": "إطار iframe خارجي مشبوه", "risk": "قد يستخدم لإدخال محتوى ضار من مصدر آخر.", "points": 10 },
]

# --- دالة التحليل الأمني ---
def perform_security_scan(link):
    suspicious_points = 0
    page_content = None 
    final_link = link 
    violated_rules = []
    page_content_warning = "تم تهيئة التحليل." 
    
    # 1. فحص الاتصال بالرابط (مهلة 5 ثوانٍ)
    try:
        response = requests.get(link, timeout=5, allow_redirects=True) 
        status_code = response.status_code
        final_link = response.url
        page_content = response.text 
        
        # قواعد سلوك الاتصال (قاعدتان إضافيتان)
        if len(response.history) > 3:
            suspicious_points += 15
            violated_rules.append({"name": "إعادة توجيه مفرطة", "risk_description": f"تمت {len(response.history)} عملية إعادة توجيه. (مشبوه).", "points_added": 15})

        if status_code != 200:
            status_points = 20 if status_code in [403, 404] else 8
            suspicious_points += status_points
            violated_rules.append({"name": "خطأ حالة الاتصال (Status Code)", "risk_description": f"الرابط يسبب خطأ {status_code}. (مشبوه).", "points_added": status_points})
            page_content_warning = f"تحذير: الرابط يسبب خطأ {status_code}."
        else:
            page_content_warning = f"تم جلب محتوى الصفحة بنجاح. (الحالة: {status_code})"
            
    except requests.exceptions.RequestException as e:
        suspicious_points += 30 
        violated_rules.append({"name": "فشل حاد في الاتصال/مهلة", "risk_description": f"فشل الاتصال بالخادم بعد 5 ثوانٍ، مما يشير إلى حظر أو عدم وجود خادم. ({type(e).__name__})", "points_added": 30})
        page_content_warning = f"خطأ حاد في الاتصال بالرابط أو حدوث مهلة. (تم إضافة 30 نقطة خطر)"
        final_link = link 
        page_content = "" # مهم: لتشغيل قواعد الرابط فقط
        
    # 2. تطبيق جميع القواعد الأمنية المتبقية
    link_for_rules = final_link
    content_to_check = page_content

    for rule in SECURITY_RULES:
        try:
            if rule["check"](link_for_rules, content_to_check):
                if rule["name"] not in [v['name'] for v in violated_rules]:
                    suspicious_points += rule["points"] 
                    violated_rules.append({
                        "name": rule["name"],
                        "risk_description": rule["risk"],
                        "points_added": rule["points"]
                    })
        except Exception:
            pass

    # 3. تحديد مستوى الخطورة
    risk_score = "Low"
    result_message = "🟢 آمن: لم يتم اكتشاف مخاطر واضحة بناءً على التحليل عالي الدقة."

    if suspicious_points > 100: 
        risk_score = "Critical"
        result_message = "🔴 خطر حرج جداً! تجاوزت النقاط 100، مما يشير إلى مؤشرات قوية جداً على التصيد أو البرامج الضارة. **يجب تجنبه تماماً.**"
    elif suspicious_points > 50: 
        risk_score = "High"
        result_message = "🔥 خطر عالٍ! تم اكتشاف مخالفات هيكلية وسلوكية متعددة. يفضل تجنبه تماماً."
    elif suspicious_points > 20: 
        risk_score = "Medium"
        result_message = "⚠️ خطر متوسط. يحتوي على بعض العناصر المشبوهة التي تقلل من الثقة به. يجب استخدامه بحذر شديد."
    
    # 4. إعادة النتيجة 
    return {
        "status": "success" if suspicious_points <= 20 else "warning" if suspicious_points <= 50 else "error",
        "message": f"تحليل مكتمل بدقة قصوى. تم تطبيق {len(SECURITY_RULES) + 2} قاعدة فحص.",
        "link_input": link, 
        "link_final": link_for_rules, 
        "result_message": result_message,
        "risk_score": risk_score,
        "suspicious_points": suspicious_points,
        "detected_warnings": len(violated_rules), 
        "page_content_status": page_content_warning,
        "violated_rules": violated_rules 
    }

# --- نقاط النهاية ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_link():
    try:
        data = request.get_json()
        link_to_analyze = data.get('link')
    except Exception:
        return jsonify({"status": "critical_error", "message": "خطأ في معالجة بيانات الطلب (JSON).", "error_code": 400}), 400

    if not link_to_analyze or link_to_analyze.strip() == "":
        return jsonify({"status": "validation_error", "message": "❌ فشل التحقق: الرجاء إدخال رابط.", "error_code": 400}), 400

    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    if url(link_to_analyze) is not True:
         return jsonify({"status": "validation_error", "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.", "error_code": 400}), 400
    
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

if __name__ == '__main__':
    # للتشغيل على Parrot OS محلياً
    app.run(debug=True, host='0.0.0.0', port=5000)
