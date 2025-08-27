import re, math, hashlib, requests, secrets, string

# ---------- helpers (entropy, pwned, crack time, scoring) ----------
def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32
    if charset == 0:
        return 0.0
    return round(len(password) * math.log2(charset), 2)

def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "< 1 second"
    minute, hour, day, year = 60, 3600, 86400, 31536000
    if seconds < minute: return f"{seconds:.2f} seconds"
    if seconds < hour: return f"{seconds/60:.2f} minutes"
    if seconds < day: return f"{seconds/hour:.2f} hours"
    if seconds < year: return f"{seconds/day:.2f} days"
    yrs = seconds / year
    if yrs < 100: return f"{yrs:.2f} years"
    if yrs < 1e6: return f"{yrs/1e3:.2f} thousand years"
    return f"{yrs/1e6:.2f} million years"

def estimate_crack_times(entropy_bits: float) -> dict:
    attempts = 2 ** max(0, entropy_bits - 1)
    rates = {
        "online_throttled_100_per_sec": 1e2,
        "online_unthrottled_1k_per_sec": 1e3,
        "offline_fast_1e10_per_sec": 1e10,
        "offline_superfast_1e14_per_sec": 1e14,
    }
    return {k: humanize_seconds(attempts / r) for k, r in rates.items()}

def check_pwned(password: str) -> int:
    """Return count of occurrences in HIBP (0 if none or on request failure)."""
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = requests.get(url, timeout=5)
        if res.status_code != 200:
            return 0
        for line in res.text.splitlines():
            parts = line.split(':')
            if len(parts) >= 2 and parts[0] == suffix:
                return int(parts[1])
    except requests.RequestException:
        return 0
    return 0

def score_password(password: str, pwned_count: int, entropy_bits: float) -> dict:
    score = 0
    L = len(password)
    if L >= 16: score += 25
    elif L >= 12: score += 15
    elif L >= 8: score += 8

    types = sum(bool(re.search(p, password)) for p in [r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]"])
    score += types * 10
    score += min(30, int(entropy_bits / 3))
    if pwned_count > 0: score = max(0, score - 40)

    score = max(0, min(100, score))
    cls = "weak" if score < 35 else "medium" if score < 70 else "strong"
    return {"percent": score, "class": cls, "types": types}

# ---------- password generator ----------
def generate_password(length: int = 16, upper=True, digits=True, special=True) -> str:
    alphabet = string.ascii_lowercase
    if upper: alphabet += string.ascii_uppercase
    if digits: alphabet += string.digits
    if special: alphabet += "!@#$%^&*()-_+=~[]{}<>?/|"
    pw = []
    if upper: pw.append(secrets.choice(string.ascii_uppercase))
    if digits: pw.append(secrets.choice(string.digits))
    if special: pw.append(secrets.choice("!@#$%^&*()-_+=~[]{}<>?/|"))
    while len(pw) < length:
        pw.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(pw)
    return ''.join(pw[:length])
