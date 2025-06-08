from flask import Flask, request, jsonify
from flask_cors import CORS
CORS(app)

app = Flask(__name__)
CORS(app)

def simple_phishing_check(url):
    url = url.lower()
    blacklist_keywords = ['login', 'secure', 'update', 'verify', 'account']
    trusted_domains = ['naver.com', 'google.com', 'daum.net', 'kakao.com', 'youtube.com']

    if not url.startswith("http://") and not url.startswith("https://"):
        return "[주의] 잘못된 URL 형식입니다."

    for word in blacklist_keywords:
        if word in url and not any(td in url for td in trusted_domains):
            return "[경고] 피싱 가능성이 있는 URL입니다."

    for td in trusted_domains:
        if td in url:
            return "[정상] 신뢰된 도메인입니다."

    return "[주의] 알 수 없는 사이트입니다."

@app.route("/check", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url")
    result = simple_phishing_check(url)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run()
