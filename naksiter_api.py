from flask import Flask, request, jsonify
from urllib.parse import urlparse
import requests
import re
import html
import time
import os
import openai

app = Flask(__name__)

DANGER_KEYWORDS = ["login", "secure", "verify", "account", "update", "confirm"]
TRUSTED_DOMAINS = ["naver.com", "kakao.com", "google.com", "daum.net"]

reports = []
report_counts = {}
report_ips = {}

openai.api_key = os.getenv("GPT_API_KEY")

def is_similar_domain(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    return any(host.endswith(trusted) for trusted in TRUSTED_DOMAINS)

def extract_text_features(html_str):
    tags = re.findall(r'<(title|meta|form|input|button)[^>]*>(.*?)</?\\1?>?', html_str, re.I|re.S)
    visible_text = html.unescape(' '.join([text for tag, text in tags]))
    return visible_text[:1000]

def prompt_gpt_analysis(summary_text):
    return f'''이 웹페이지는 다음과 같은 내용을 담고 있습니다:\n\n"{summary_text}"\n\n해당 페이지가 피싱 가능성이 있는지 판단해주세요.\n- 로그인 폼이 있고\n- 실제 도메인과 다른 주소일 경우\n'위험',\n- 광고성이나 애매하면 '경고',\n- 정상적이면 '정상' 으로 답변해주세요.'''

@app.route("/check")
def check():
    url = request.args.get("url", "").strip()
    if not url.startswith("http"):
        url = "https://" + url

    score = sum(1 for keyword in DANGER_KEYWORDS if keyword in url.lower())
    trusted = is_similar_domain(url)
    report_count = report_counts.get(url, 0)

    # ✅ 실제 접속 확인 추가
    try:
        resp = requests.get(url, timeout=3)
        reachable = resp.status_code < 500
    except:
        reachable = False

    if trusted and reachable:
        result = "[정상] 신뢰된 도메인입니다."
    elif trusted and not reachable:
        result = "[주의] 신뢰 도메인이지만 현재 접속 불가"
    elif score >= 3:
        result = "[위험] 피싱 가능성이 매우 높습니다."
    elif score >= 1:
        result = "[경고] 의심스러운 URL입니다."
    elif report_count >= 3:
        result = "[주의] 사용자 신고가 누적된 URL입니다."
    else:
        result = "[정상] 안전한 링크로 판단됩니다."

    return jsonify({"result": result, "신고수": report_count})


@app.route("/preview")
def preview():
    url = request.args.get("url", "").strip()
    if not url.startswith("http"):
        url = "https://" + url  # ✅ 자동 보정 추가

    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        summary = extract_text_features(r.text)
        prompt = prompt_gpt_analysis(summary)
        gpt_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "당신은 보안 전문가입니다."},
                {"role": "user", "content": prompt}
            ]
        )
        answer = gpt_response["choices"][0]["message"]["content"]
        return jsonify({"preview": answer})
    except Exception as e:
        return jsonify({"preview": f"[오류] 사이트 분석 실패 - {str(e)}"})


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    url = data.get("url", "")
    user_ip = request.remote_addr
    now = time.time()

    if now - report_ips.get(user_ip, 0) < 60:
        return jsonify({"message": "너무 자주 신고할 수 없습니다. 잠시 후 다시 시도해주세요."})
    report_ips[user_ip] = now

    if url:
        reports.append({"url": url, "ip": user_ip, "timestamp": now})
        report_counts[url] = report_counts.get(url, 0) + 1
        return jsonify({"message": "신고가 접수되었습니다."})
    return jsonify({"message": "잘못된 요청입니다."})

@app.route("/logs")
def logs():
    return jsonify({"신고내역": reports[-10:]})

@app.route("/ui")
def ui_page():
    return open("naksiter_ui_page.html", encoding="utf-8").read()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
