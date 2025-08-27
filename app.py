from flask import Flask, render_template, request, jsonify
from password_utils import (
    calculate_entropy,
    check_pwned,
    estimate_crack_times,
    score_password,
    generate_password
)

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index_page():
    return render_template("index.html")

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json() or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify({"error": "password must be string"}), 400

    entropy = calculate_entropy(password)
    pwned_count = check_pwned(password) if password else 0
    crack_times = estimate_crack_times(entropy)
    score = score_password(password, pwned_count, entropy)

    suggestions = []
    if len(password) < 8:
        suggestions.append("Tăng độ dài ít nhất >=8 (tốt nhất >=12).")
    if score["types"] < 4:
        suggestions.append("Đa dạng ký tự: chữ hoa, chữ thường, số, ký tự đặc biệt.")
    if pwned_count > 0:
        suggestions.append("Mật khẩu này đã xuất hiện trong các vụ leak — KHÔNG DÙNG.")
    if entropy < 40:
        suggestions.append("Entropy thấp — tăng độ dài / đa dạng ký tự.")

    return jsonify({
        "entropy_bits": entropy,
        "pwned_count": pwned_count,
        "crack_times": crack_times,
        "score": score,
        "suggestions": suggestions
    })

@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.get_json() or {}
    length = int(data.get("length", 16))
    length = max(6, min(64, length))
    upper = bool(data.get("upper", True))
    digits = bool(data.get("digits", True))
    special = bool(data.get("special", True))
    pw = generate_password(length, upper, digits, special)
    return jsonify({"password": pw})

if __name__ == "__main__":
    app.run(debug=True)
