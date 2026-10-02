import re
from urllib.parse import urlparse

# قائمة الروابط القابلة للتقصير المعروفة
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "goo.gl"]

# الكلمات المشبوهة في الروابط
SUSPICIOUS_URL_KEYWORDS = ["login", "verify", "account", "update", "bank", "secure", "signin", "free", "claim",
                           "support", "paypal"]

# النطاقات عالية الخطورة
HIGH_RISK_TLDS = [".xyz", ".top", ".club", ".work", ".click", ".link", ".zip", ".mov"]

# الكلمات المفتاحية لمشاعر الاستعجال والاحتيال في الرسائل
URGENCY_KEYWORDS = [
    "فوراً", "عاجل", "تأكيد", "تحديث حسابك", "تم إيقاف", "تم تجميد", "حسابك البنكي",
    "فزت بـ", "جائزة", "اضغط على الرابط", "إعادة تفعيل", "كلمة المرور", "بطاقة الائتمان",
    "urgently", "immediately", "account suspended", "verify your account", "winner", "prize", "click here"
]


def generate_ai_explanation(score: int, level: str, indicators: list, input_type: str) -> str:
    """توليد شرح ذكي مبسط يوضح سبب النتيجة للمستخدم العادي (باستخدام وسوم HTML لتنسيق خط عريض)"""
    if score >= 65:
        explanation = (
            f"🤖 <b>تحليل الذكاء الاصطناعي:</b> تم تصنيف هذا الـ ({input_type}) بكونه <b>عالي الخطورة جداً ({score}/100)</b>. "
            f"يعتمد التهديد المرصود على تقنيات الهندسة الاجتماعية والاستدراج الاحتيالي، حيث رصد النظام {len(indicators)} مؤشرات خطرة "
            f"تستهدف توجيه الضحية لإفشاء معلومات حساسة أو زيارة وجهات مجهولة. يُنصح بعدم التفاعل نهائياً."
        )
    elif score >= 30:
        explanation = (
            f"🤖 <b>تحليل الذكاء الاصطناعي:</b> تم تصنيف المدخل بمستوى <b>خطورة متوسطة ({score}/100)</b>. "
            f"يحتوي العنصر على بعض الخصائص غير المألوفة مثل استخدام بروتوكول غير مشفر أو عبارات حث على الإجراء. "
            f"يُرجى التحقق بدقة من الهوية الحقيقية للمرسل أو اسم النطاق قبل متابعة التفاعل."
        )
    else:
        explanation = (
            f"🤖 <b>تحليل الذكاء الاصطناعي:</b> يُظهر الفحص المبدئي أن المدخل <b>آمن وسليم ({score}/100)</b> "
            f"ولم يتم تسجيل أي مؤشرات احتيال أو روابط خبيثة مألوفة. يظل من الممارسات الآمنة التأكد دائماً من الاتصال عبر القنوات الرسمية."
        )
    return explanation


def evaluate_url_risk(url: str) -> dict:
    score = 0
    indicators = []

    clean_url = url.strip().lower()

    # 1. IP address check
    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, clean_url):
        score += 40
        indicators.append("استخدام عنوان IP مباشر بدلاً من اسم نطاق موثوق (Direct IP Address)")

    # 2. URL shorteners
    if any(shortener in clean_url for shortener in URL_SHORTENERS):
        score += 25
        indicators.append("استخدام خدمة اختصار الروابط لإخفاء الوجهة الحقيقية (URL Shortener)")

    # 3. Missing HTTPS
    if clean_url.startswith("http://"):
        score += 15
        indicators.append("الرابط لا يستخدم اتصالاً مشفراً ومحميًا (Missing HTTPS)")

    # 4. Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in clean_url]
    if found_keywords:
        score += 20
        indicators.append(f"تضمن الرابط كلمات استدراج مشبوهة: ({', '.join(found_keywords)})")

    # 5. High risk TLDs
    if any(clean_url.endswith(tld) or (tld + "/") in clean_url for tld in HIGH_RISK_TLDS):
        score += 20
        indicators.append("اسم النطاق يستخدم امتداداً عالي الخطورة (High-Risk TLD)")

    # 6. Subdomains
    parsed = urlparse(clean_url if "://" in clean_url else "http://" + clean_url)
    domain_parts = parsed.netloc.split('.')
    if len(domain_parts) > 3:
        score += 15
        indicators.append("تعدد النطاقات الفرعية بشكل غير معتاد (Excessive Subdomains)")

    score = min(score, 100)

    if score >= 65:
        level = "High Risk"
        recommendation = "🚨 خطورة عالية جداً! تجنب فتح هذا الرابط مطلقاً ولا تدخل أي بيانات شخصية."
    elif score >= 30:
        level = "Medium Risk"
        recommendation = "⚠️ خطورة متوسطة. يرجى توخي الحذر والتحقق من مصدر الرابط قبل التفاعل معه."
    else:
        level = "Low Risk"
        recommendation = "✅ الرابط يتطابق مع معايير الأمان المبدئية، لكن يرجى التأكد دائماً من المصدر."

    actual_indicators = indicators if indicators else ["لم يتم العثور على مؤشرات تهديد مباشرة."]
    ai_explanation = generate_ai_explanation(score, level, actual_indicators, "الرابط")

    return {
        "score": score,
        "level": level,
        "indicators": actual_indicators,
        "recommendation": recommendation,
        "ai_explanation": ai_explanation
    }


def evaluate_message_risk(message: str) -> dict:
    score = 0
    indicators = []

    clean_msg = message.strip()

    # 1. Urgency keywords
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw.lower() in clean_msg.lower()]
    if found_urgency:
        score += 35
        indicators.append(f"تحتوي الرسالة على كلمات استعجال/تهديد/إغراء: ({', '.join(found_urgency)})")

    # 2. Embedded URLs
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    found_urls = re.findall(url_pattern, clean_msg)
    if found_urls:
        score += 30
        indicators.append(f"تتضمن الرسالة رابطاً خارجياً مدمجاً: ({found_urls[0]})")

        if any(sh in found_urls[0].lower() for sh in URL_SHORTENERS):
            score += 20
            indicators.append("الرابط المدمج في الرسالة مختصر ومجهول الوجهة")

    # 3. Sensitive data request
    sensitive_terms = ["كلمة السر", "رقم البطاقة", "OTP", "رمز التحقق", "password", "pin", "cvv"]
    if any(term in clean_msg.lower() for term in sensitive_terms):
        score += 30
        indicators.append("الرسالة تطلب الإفصاح عن بيانات حساسة أو رموز تحقق (OTP/Credentials)")

    score = min(score, 100)

    if score >= 65:
        level = "High Risk"
        recommendation = "🚨 رسالة احتيالية عالية الخطورة! لا تضغط على أي رابط ولا تشارك أي بيانات حساسة."
    elif score >= 30:
        level = "Medium Risk"
        recommendation = "⚠️ رسالة مشبوهة. تأكد من الجهة المرسلة عبر قنوات الاتصال الرسمية فقط."
    else:
        level = "Low Risk"
        recommendation = "✅ لا تحتوي الرسالة على أنماط احتيال مألوفة."

    actual_indicators = indicators if indicators else ["الرسالة سليمة ولا تحتوي على مؤشرات تهديد ظاهرة."]
    ai_explanation = generate_ai_explanation(score, level, actual_indicators, "الرسالة")

    return {
        "score": score,
        "level": level,
        "indicators": actual_indicators,
        "recommendation": recommendation,
        "ai_explanation": ai_explanation
    }
