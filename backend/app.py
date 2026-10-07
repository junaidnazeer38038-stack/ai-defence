from flask import Flask, send_from_directory, request, jsonify, send_file, g
from flask_cors import CORS
from google import genai
from groq import Groq
from dotenv import load_dotenv
try:
    from backend.url_scanner import scan_url
except ImportError:
    from url_scanner import scan_url

import os
import hashlib
import re
import socket
import ipaddress
import json
import io
import uuid
import urllib.request
import urllib.parse
from datetime import datetime


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

CORS(
    app,
    supports_credentials=True
)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# ============================================================
# SUPABASE
# ============================================================

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).strip().rstrip("/")

SUPABASE_KEY = os.getenv(
    "SUPABASE_KEY",
    ""
).strip()


def supabase_enabled():
    return bool(
        SUPABASE_URL and
        SUPABASE_KEY
    )


def supabase_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }


def supabase_request(
    method,
    endpoint,
    data=None
):
    if not supabase_enabled():
        return None

    url = (
        SUPABASE_URL +
        "/rest/v1/" +
        endpoint
    )

    body = None

    if data is not None:
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        method=method
    )

    for key, value in supabase_headers().items():
        req.add_header(key, value)

    if method == "POST":
        req.add_header(
            "Prefer",
            "return=minimal"
        )

    try:
        with urllib.request.urlopen(
            req,
            timeout=15
        ) as response:

            raw = response.read().decode(
                "utf-8"
            )

            if not raw:
                return []

            return json.loads(raw)

    except Exception as e:
        print(
            "Supabase error:",
            e
        )
        return None


# ============================================================
# AI KEYS
# ============================================================

GEMINI_API_KEYS = [
    os.getenv("GEMINI_API_KEY"),
    os.getenv("GEMINI_API_KEY_1"),
    os.getenv("GEMINI_API_KEY_2")
]

GEMINI_API_KEYS = [
    key.strip()
    for key in GEMINI_API_KEYS
    if key and key.strip()
]

GROQ_API_KEY = os.getenv(
    "GROQ_API_KEY"
)


# ============================================================
# AI CLIENTS
# ============================================================

gemini_clients = []

for key in GEMINI_API_KEYS:

    try:

        gemini_clients.append(
            genai.Client(
                api_key=key
            )
        )

    except Exception as e:

        print(
            "Gemini client error:",
            e
        )


groq_client = None

if GROQ_API_KEY:

    try:

        groq_client = Groq(
            api_key=GROQ_API_KEY
        )

    except Exception as e:

        print(
            "Groq client error:",
            e
        )


# ============================================================
# MODELS
# ============================================================

GEMINI_MODEL = "gemini-3.8-flash"

GROQ_MODEL = "openai/gpt-oss-20b"


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are Cyber Security AI.

You are a defensive cybersecurity assistant.

Help users with:

- Cybersecurity education
- Online safety
- Privacy
- Phishing detection
- Suspicious URLs
- Malware awareness
- Password security
- Network security
- Security best practices
- Safe browsing
- Defensive security analysis

Only provide defensive, educational and authorized
cybersecurity guidance.

Do NOT provide instructions for:

- Stealing passwords
- Credential theft
- Malware creation
- Ransomware
- Unauthorized access
- Account takeover
- Bypassing authentication
- Exploiting real systems
- Destructive attacks
- Evading security systems

When explaining a security issue:

1. Explain what happened.
2. Explain the risk.
3. Give a risk level if possible.
4. Explain why it may be dangerous.
5. Give safe defensive recommendations.
6. Keep the answer understandable for beginners.
"""


# ============================================================
# USER ID
# ============================================================

def get_user_id():

    user_id = request.cookies.get(
        "cyber_user_id"
    )

    if not user_id:

        user_id = str(
            uuid.uuid4()
        )

        g.new_user_id = user_id

    return user_id


# ============================================================
# LOCAL HISTORY FALLBACK
# ============================================================

def load_all_history():

    try:

        if not os.path.exists(
            HISTORY_FILE
        ):
            return {}

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(
            data,
            dict
        ):
            return data

        return {}

    except Exception as e:

        print(
            "History load error:",
            e
        )

        return {}


def local_load_history():

    user_id = get_user_id()

    all_history = load_all_history()

    history = all_history.get(
        user_id,
        []
    )

    if isinstance(
        history,
        list
    ):
        return history

    return []


def local_save_history(entry):

    user_id = get_user_id()

    all_history = load_all_history()

    if user_id not in all_history:

        all_history[user_id] = []

    all_history[user_id].insert(
        0,
        entry
    )

    all_history[user_id] = (
        all_history[user_id][:100]
    )

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                all_history,
                file,
                indent=2,
                ensure_ascii=False
            )

        return True

    except Exception as e:

        print(
            "History save error:",
            e
        )

        return False


def local_clear_history():

    user_id = get_user_id()

    all_history = load_all_history()

    all_history[user_id] = []

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                all_history,
                file,
                indent=2,
                ensure_ascii=False
            )

        return True

    except Exception as e:

        print(
            "History clear error:",
            e
        )

        return False


# ============================================================
# DATABASE HISTORY
# ============================================================

def load_history():

    user_id = get_user_id()

    if not supabase_enabled():

        return local_load_history()

    encoded_user = urllib.parse.quote(
        user_id,
        safe=""
    )

    endpoint = (
        "scan_history"
        f"?user_id=eq.{encoded_user}"
        "&select=entry,created_at"
        "&order=created_at.desc"
        "&limit=100"
    )

    result = supabase_request(
        "GET",
        endpoint
    )

    if result is None:

        return local_load_history()

    history = []

    for row in result:

        entry = row.get(
            "entry"
        )

        if isinstance(
            entry,
            dict
        ):
            history.append(entry)

    return history


def save_history_entry(entry):

    user_id = get_user_id()

    if not supabase_enabled():

        return local_save_history(
            entry
        )

    data = {
        "user_id": user_id,
        "entry": entry
    }

    result = supabase_request(
        "POST",
        "scan_history",
        data
    )

    if result is None:

        print(
            "Supabase save failed."
        )

        return local_save_history(
            entry
        )

    return True


def clear_history():

    user_id = get_user_id()

    if not supabase_enabled():

        return local_clear_history()

    encoded_user = urllib.parse.quote(
        user_id,
        safe=""
    )

    endpoint = (
        "scan_history"
        f"?user_id=eq.{encoded_user}"
    )

    result = supabase_request(
        "DELETE",
        endpoint
    )

    if result is None:

        return local_clear_history()

    return True


# ============================================================
# COOKIE
# ============================================================

@app.after_request
def set_user_cookie(response):

    user_id = getattr(
        g,
        "new_user_id",
        None
    )

    if user_id:

        response.set_cookie(
            "cyber_user_id",
            user_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax",
            secure=request.is_secure
        )

    return response


# ============================================================
# GENERAL HELPERS
# ============================================================

def now():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def clamp_score(score):

    try:

        score = int(score)

    except Exception:

        score = 0

    return max(
        0,
        min(
            100,
            score
        )
    )


def risk_level(score):

    score = clamp_score(
        score
    )

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def get_status(score):

    score = clamp_score(
        score
    )

    if score >= 80:
        return "Critical Risk"

    if score >= 60:
        return "High Risk"

    if score >= 30:
        return "Medium Risk"

    return "Safe"


def add_history(
    scan_type,
    target,
    score,
    result,
    summary=""
):

    score = clamp_score(
        score
    )

    entry = {

        "id": hashlib.sha256(
            (
                f"{scan_type}-"
                f"{target}-"
                f"{datetime.now().timestamp()}"
            ).encode()
        ).hexdigest()[:12],

        "type": scan_type,

        "target": target,

        "risk_score": score,

        "risk_level": risk_level(
            score
        ),

        "status": get_status(
            score
        ),

        "summary": summary,

        "result": result,

        "timestamp": now()
    }

    save_history_entry(
        entry
    )

    return entry


# ============================================================
# AI
# ============================================================

def ask_gemini(prompt):

    if not gemini_clients:

        print(
            "Gemini is not configured."
        )

        return None

    full_prompt = (
        SYSTEM_PROMPT +
        "\n\nUser request:\n" +
        prompt
    )

    for index, client in enumerate(
        gemini_clients,
        start=1
    ):

        try:

            response = (
                client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=full_prompt
                )
            )

            answer = getattr(
                response,
                "text",
                None
            )

            if answer:

                print(
                    f"Gemini key {index} responded."
                )

                return answer.strip()

        except Exception as e:

            print(
                f"Gemini key {index} error:",
                e
            )

    return None


def ask_groq(prompt):

    if not groq_client:

        print(
            "Groq is not configured."
        )

        return None

    try:

        response = (
            groq_client
            .chat
            .completions
            .create(
                model=GROQ_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3
            )
        )

        if not response.choices:

            return None

        answer = (
            response
            .choices[0]
            .message
            .content
        )

        if answer:

            print(
                "Groq responded."
            )

            return answer.strip()

    except Exception as e:

        print(
            "Groq error:",
            e
        )

    return None


def ask_ai(prompt):

    answer = ask_groq(
        prompt
    )

    if answer:

        return answer, "Groq"

    answer = ask_gemini(
        prompt
    )

    if answer:

        return answer, "Gemini"

    return (
        "AI service is temporarily unavailable. Please try again.",
        "System"
    )


# ============================================================
# FRONTEND
# ============================================================

@app.route("/")
def home():

    return send_from_directory(
        FRONTEND_FOLDER,
        "index.html"
    )


@app.route("/<path:path>")
def frontend_files(path):

    return send_from_directory(
        FRONTEND_FOLDER,
        path
    )


# ============================================================
# STATUS
# ============================================================

@app.route(
    "/api/status",
    methods=["GET"]
)
def api_status():

    return jsonify({

        "success": True,

        "status": "online",

        "ai": {

            "gemini": bool(
                gemini_clients
            ),

            "groq": bool(
                groq_client
            )

        },

        "database": (
            "Supabase"
            if supabase_enabled()
            else "Local"
        ),

        "features": {

            "chat": True,

            "url_scanner": True,

            "file_scanner": True,

            "phishing_detector": True,

            "password_checker": True,

            "ip_domain_info": True,

            "security_report": True,

            "threat_alerts": True,

            "dashboard": True,

            "history": True

        },

        "time": now()

    })


# ============================================================
# AI CHAT
# ============================================================

@app.route(
    "/api/chat",
    methods=["POST"]
)
def chat():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        message = str(
            data.get(
                "message",
                ""
            )
        ).strip()

        if not message:

            return jsonify({
                "success": False,
                "error": "Message is required."
            }), 400

        answer, provider = ask_ai(
            message
        )

        return jsonify({

            "success": True,

            "answer": answer,

            "response": answer,

            "provider": provider

        })

    except Exception as e:

        print(
            "Chat error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to process your request."

        }), 500


# ============================================================
# URL SCANNER
# ============================================================

@app.route(
    "/api/scan-url",
    methods=["POST"]
)
def scan_url_api():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        url = str(
            data.get(
                "url",
                ""
            )
        ).strip()

        if not url:

            return jsonify({
                "success": False,
                "error": "URL is required."
            }), 400

        result = scan_url(
            url
        )

        if not isinstance(
            result,
            dict
        ):
            result = {
                "message": str(
                    result
                )
            }

        score = result.get(
            "risk_score",
            result.get(
                "score",
                0
            )
        )

        score = clamp_score(
            score
        )

        entry = add_history(
            "URL Scan",
            url,
            score,
            result,
            "URL security analysis completed."
        )

        result["risk_score"] = score
        result["risk_level"] = risk_level(
            score
        )
        result["status"] = get_status(
            score
        )

        return jsonify({

            "success": True,

            "result": result,

            "history_entry": entry

        })

    except Exception as e:

        print(
            "URL scan error:",
            e
        )

        return jsonify({

            "success": False,

            "error": str(e)

        }), 500


# ============================================================
# FILE SCANNER
# ============================================================

@app.route(
    "/api/scan-file",
    methods=["POST"]
)
def scan_file():

    try:

        uploaded = request.files.get(
            "file"
        )

        if not uploaded:

            return jsonify({
                "success": False,
                "error": "Please select a file."
            }), 400

        filename = uploaded.filename or "unknown"

        filename_lower = filename.lower()

        file_data = uploaded.read()

        file_size = len(
            file_data
        )

        sha256_hash = hashlib.sha256(
            file_data
        ).hexdigest()

        md5_hash = hashlib.md5(
            file_data
        ).hexdigest()

        extension = os.path.splitext(
            filename_lower
        )[1].lower()

        dangerous_extensions = {

            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com",
            ".msi",
            ".dll",
            ".ps1",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".wsf",
            ".wsh",
            ".hta",
            ".jar",
            ".apk"

        }

        suspicious_extensions = {

            ".zip",
            ".rar",
            ".7z",
            ".iso",
            ".img",
            ".docm",
            ".xlsm",
            ".pptm"

        }

        score = 0

        indicators = []

        if extension in dangerous_extensions:

            score += 70

            indicators.append(
                "Potentially executable or script-based file type."
            )

        elif extension in suspicious_extensions:

            score += 35

            indicators.append(
                "Archive or macro-enabled file type requires caution."
            )

        else:

            indicators.append(
                "No dangerous file extension detected."
            )

        if file_size == 0:

            score += 15

            indicators.append(
                "File is empty."
            )

        if file_size > 100 * 1024 * 1024:

            score += 10

            indicators.append(
                "File is unusually large."
            )

        score = clamp_score(
            score
        )

        result = {

            "file_name": filename,

            "file_size": file_size,

            "file_size_kb": round(
                file_size / 1024,
                2
            ),

            "extension": (
                extension
                if extension
                else "No extension"
            ),

            "sha256": sha256_hash,

            "md5": md5_hash,

            "mime_type": (
                uploaded.mimetype
                or "Unknown"
            ),

            "risk_score": score,

            "risk_level": risk_level(
                score
            ),

            "status": get_status(
                score
            ),

            "indicators": indicators,

            "safe": score < 30

        }

        entry = add_history(
            "File Scan",
            filename,
            score,
            result,
            "File security analysis completed."
        )

        return jsonify({

            "success": True,

            "result": result,

            "history_entry": entry

        })

    except Exception as e:

        print(
            "File scan error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to scan file."

        }), 500


# ============================================================
# PHISHING DETECTOR
# ============================================================

@app.route(
    "/api/detect-phishing",
    methods=["POST"]
)
def detect_phishing():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        text = str(
            data.get(
                "text",
                data.get(
                    "url",
                    ""
                )
            )
        ).strip()

        if not text:

            return jsonify({
                "success": False,
                "error": "URL or text is required."
            }), 400

        lower_text = text.lower()

        score = 0

        indicators = []

        phishing_words = [

            "verify your account",
            "verify account",
            "urgent action",
            "login immediately",
            "confirm password",
            "reset password",
            "account suspended",
            "account locked",
            "click here",
            "security alert",
            "claim reward",
            "free gift",
            "winner",
            "payment failed"

        ]

        for word in phishing_words:

            if word in lower_text:

                score += 12

                indicators.append(
                    f"Suspicious phrase detected: {word}"
                )

        url_pattern = (
            r"https?://[^\s]+"
            r"|www\.[^\s]+"
        )

        urls = re.findall(
            url_pattern,
            text,
            re.IGNORECASE
        )

        if urls:

            for url in urls:

                if "@" in url:

                    score += 20

                    indicators.append(
                        "URL contains an @ symbol."
                    )

                if len(url) > 100:

                    score += 10

                    indicators.append(
                        "URL is unusually long."
                    )

        score = clamp_score(
            score
        )

        if score >= 60:

            verdict = "Likely Phishing"

        elif score >= 30:

            verdict = "Suspicious"

        else:

            verdict = "Low Risk"

        result = {

            "input": text,

            "verdict": verdict,

            "risk_score": score,

            "risk_level": risk_level(
                score
            ),

            "status": get_status(
                score
            ),

            "indicators": indicators,

            "urls_found": urls

        }

        entry = add_history(
            "Phishing Detection",
            text[:200],
            score,
            result,
            verdict
        )

        return jsonify({

            "success": True,

            "result": result,

            "history_entry": entry

        })

    except Exception as e:

        print(
            "Phishing error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to analyze input."

        }), 500


# ============================================================
# PASSWORD CHECKER
# ============================================================

@app.route(
    "/api/check-password",
    methods=["POST"]
)
def check_password():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        password = str(
            data.get(
                "password",
                ""
            )
        )

        if not password:

            return jsonify({
                "success": False,
                "error": "Password is required."
            }), 400

        score = 0

        checks = []

        if len(password) >= 8:

            score += 20

            checks.append(
                "Good length."
            )

        else:

            checks.append(
                "Use at least 8 characters."
            )

        if len(password) >= 12:

            score += 15

        if re.search(
            r"[A-Z]",
            password
        ):

            score += 15

            checks.append(
                "Contains uppercase letters."
            )

        else:

            checks.append(
                "Add uppercase letters."
            )

        if re.search(
            r"[a-z]",
            password
        ):

            score += 15

        if re.search(
            r"\d",
            password
        ):

            score += 15

            checks.append(
                "Contains numbers."
            )

        else:

            checks.append(
                "Add numbers."
            )

        if re.search(
            r"[^A-Za-z0-9]",
            password
        ):

            score += 20

            checks.append(
                "Contains special characters."
            )

        else:

            checks.append(
                "Add special characters."
            )

        score = clamp_score(
            score
        )

        if score >= 80:

            strength = "Very Strong"

        elif score >= 60:

            strength = "Strong"

        elif score >= 40:

            strength = "Medium"

        else:

            strength = "Weak"

        # Password is intentionally NOT saved.
        result = {

            "score": score,

            "risk_score": 100 - score,

            "strength": strength,

            "checks": checks,

            "recommendations": [

                "Use a long unique password.",
                "Avoid names and birthdays.",
                "Do not reuse passwords.",
                "Use a password manager.",
                "Enable multi-factor authentication."

            ]

        }

        return jsonify({

            "success": True,

            "result": result

        })

    except Exception as e:

        print(
            "Password error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to check password."

        }), 500


# ============================================================
# IP / DOMAIN INFO
# ============================================================

@app.route(
    "/api/ip-domain-info",
    methods=["POST"]
)
def ip_domain_info():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        target = str(
            data.get(
                "target",
                data.get(
                    "domain",
                    data.get(
                        "ip",
                        ""
                    )
                )
            )
        ).strip()

        if not target:

            return jsonify({

                "success": False,

                "error": "IP address or domain is required."

            }), 400

        target_clean = target

        target_clean = re.sub(
            r"^https?://",
            "",
            target_clean,
            flags=re.IGNORECASE
        )

        target_clean = target_clean.split(
            "/"
        )[0]

        target_clean = target_clean.split(
            ":"
        )[0]

        hostname = ""

        reverse_dns = ""

        ip_address = ""

        network_type = ""

        address_type = ""

        ip_version = ""

        is_private = False

        is_loopback = False

        is_reserved = False

        # ----------------------------------------------------
        # IP INPUT
        # ----------------------------------------------------

        try:

            ip_obj = ipaddress.ip_address(
                target_clean
            )

            ip_address = str(
                ip_obj
            )

            hostname = socket.getfqdn(
                ip_address
            )

            if hostname == ip_address:

                hostname = ""

            try:

                reverse_dns = socket.gethostbyaddr(
                    ip_address
                )[0]

            except Exception:

                reverse_dns = hostname

            if ip_obj.version == 4:

                ip_version = "IPv4"

            else:

                ip_version = "IPv6"

            is_private = ip_obj.is_private

            is_loopback = ip_obj.is_loopback

            is_reserved = ip_obj.is_reserved

            if is_loopback:

                network_type = "Loopback"

            elif is_private:

                network_type = "Private Network"

            elif is_reserved:

                network_type = "Reserved"

            else:

                network_type = "Public Internet"

            address_type = (
                "Private"
                if is_private
                else "Public"
            )

            resolved_type = "IP Address"

        except ValueError:

            # ------------------------------------------------
            # DOMAIN INPUT
            # ------------------------------------------------

            resolved_type = "Domain"

            hostname = target_clean

            try:

                resolved = socket.gethostbyname_ex(
                    target_clean
                )

                aliases = resolved[1]

                addresses = resolved[2]

                if addresses:

                    ip_address = addresses[0]

                if aliases:

                    reverse_dns = (
                        aliases[0]
                    )

                else:

                    reverse_dns = target_clean

                try:

                    ip_obj = ipaddress.ip_address(
                        ip_address
                    )

                    ip_version = (
                        "IPv4"
                        if ip_obj.version == 4
                        else "IPv6"
                    )

                    is_private = (
                        ip_obj.is_private
                    )

                    is_loopback = (
                        ip_obj.is_loopback
                    )

                    is_reserved = (
                        ip_obj.is_reserved
                    )

                    if is_loopback:

                        network_type = "Loopback"

                    elif is_private:

                        network_type = "Private Network"

                    elif is_reserved:

                        network_type = "Reserved"

                    else:

                        network_type = "Public Internet"

                    address_type = (
                        "Private"
                        if is_private
                        else "Public"
                    )

                except Exception:

                    network_type = (
                        "Public Internet"
                    )

                    address_type = "Public"

            except Exception as dns_error:

                print(
                    "DNS lookup error:",
                    dns_error
                )

                network_type = (
                    "DNS Resolution Failed"
                )

                address_type = (
                    "Unknown"
                )

        result = {

            "target": target,

            "type": resolved_type,

            "ip_address": ip_address or "Not found",

            "hostname": hostname or "Not found",

            "reverse_dns": reverse_dns or "Not found",

            "network_type": network_type or "Unknown",

            "address_type": address_type or "Unknown",

            "ip_version": ip_version or "Unknown",

            "is_private": is_private,

            "is_loopback": is_loopback,

            "is_reserved": is_reserved,

            "dns_resolved": bool(
                ip_address
            )

        }

        # Informational feature,
        # so no unnecessary high risk score.
        score = 0

        if not ip_address:

            score = 20

        result["risk_score"] = score

        result["risk_level"] = risk_level(
            score
        )

        result["status"] = get_status(
            score
        )

        entry = add_history(
            "IP / Domain Info",
            target,
            score,
            result,
            "IP/domain information lookup completed."
        )

        return jsonify({

            "success": True,

            "result": result,

            "history_entry": entry

        })

    except Exception as e:

        print(
            "IP/domain error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to retrieve IP/domain information."

        }), 500


# ============================================================
# SECURITY REPORT
# ============================================================

@app.route(
    "/api/security-report",
    methods=["POST"]
)
def security_report():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        target = str(
            data.get(
                "target",
                "Security Environment"
            )
        )

        details = str(
            data.get(
                "details",
                ""
            )
        )

        prompt = f"""
Create a beginner-friendly defensive cybersecurity report.

Target:
{target}

Details:
{details}

Include:

1. Executive Summary
2. Risk Assessment
3. Important Findings
4. Potential Risks
5. Defensive Recommendations
6. Final Security Advice

Do not provide offensive instructions.
"""

        answer, provider = ask_ai(
            prompt
        )

        result = {

            "target": target,

            "report": answer,

            "provider": provider

        }

        return jsonify({

            "success": True,

            "result": result

        })

    except Exception as e:

        print(
            "Report error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to generate report."

        }), 500


# ============================================================
# THREAT ALERTS
# ============================================================

@app.route(
    "/api/threat-alerts",
    methods=["GET"]
)
def threat_alerts():

    alerts = [

        {
            "title": "Phishing Awareness",
            "severity": "High",
            "description":
                "Be careful with unexpected login and verification messages.",
            "time": now()
        },

        {
            "title": "Password Security",
            "severity": "Medium",
            "description":
                "Use unique passwords and enable multi-factor authentication.",
            "time": now()
        },

        {
            "title": "Suspicious Files",
            "severity": "High",
            "description":
                "Do not open unknown executable or script files.",
            "time": now()
        },

        {
            "title": "Safe Browsing",
            "severity": "Medium",
            "description":
                "Verify website addresses before entering sensitive information.",
            "time": now()
        }

    ]

    return jsonify({

        "success": True,

        "alerts": alerts

    })


# ============================================================
# HISTORY
# ============================================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def get_history():

    try:

        history = load_history()

        return jsonify({

            "success": True,

            "count": len(
                history
            ),

            "history": history

        })

    except Exception as e:

        print(
            "Get history error:",
            e
        )

        return jsonify({

            "success": False,

            "error": "Unable to load history.",

            "history": []

        }), 500


@app.route(
    "/api/history/clear",
    methods=["POST"]
)
def delete_history():

    try:

        success = clear_history()

        if success:

            return jsonify({

                "success": True,

                "message":
                    "Scan history cleared.",

                "history": []

            })

        return jsonify({

            "success": False,

            "error":
                "Unable to clear history."

        }), 500

    except Exception as e:

        print(
            "Clear history error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to clear history."

        }), 500


# ============================================================
# ADVANCED SECURITY DASHBOARD
# ============================================================

@app.route(
    "/api/security-dashboard",
    methods=["GET"]
)
def security_dashboard():

    try:

        history = load_history()

        total_scans = len(
            history
        )

        scores = []

        high_risk = 0
        medium_risk = 0
        low_risk = 0
        critical_risk = 0

        type_counts = {}

        for item in history:

            try:

                score = int(
                    item.get(
                        "risk_score",
                        0
                    )
                )

            except Exception:

                score = 0

            score = clamp_score(
                score
            )

            scores.append(
                score
            )

            if score >= 80:

                critical_risk += 1

            elif score >= 60:

                high_risk += 1

            elif score >= 30:

                medium_risk += 1

            else:

                low_risk += 1

            scan_type = item.get(
                "type",
                "Unknown"
            )

            type_counts[
                scan_type
            ] = (
                type_counts.get(
                    scan_type,
                    0
                ) + 1
            )

        average_risk = (
            round(
                sum(scores) /
                len(scores),
                1
            )
            if scores
            else 0
        )

        recent_scans = history[:10]

        dashboard = {

            "total_scans":
                total_scans,

            "average_risk":
                average_risk,

            "critical_risk":
                critical_risk,

            "high_risk":
                high_risk,

            "medium_risk":
                medium_risk,

            "low_risk":
                low_risk,

            "risk_distribution": {

                "critical":
                    critical_risk,

                "high":
                    high_risk,

                "medium":
                    medium_risk,

                "low":
                    low_risk

            },

            "scan_types":
                type_counts,

            "recent_scans":
                recent_scans,

            "database":
                (
                    "Supabase"
                    if supabase_enabled()
                    else "Local"
                )

        }

        return jsonify({

            "success": True,

            # Direct values
            "total_scans":
                total_scans,

            "average_risk":
                average_risk,

            "critical_risk":
                critical_risk,

            "high_risk":
                high_risk,

            "medium_risk":
                medium_risk,

            "low_risk":
                low_risk,

            "risk_distribution":
                dashboard[
                    "risk_distribution"
                ],

            "scan_types":
                type_counts,

            "recent_scans":
                recent_scans,

            # Nested dashboard
            "dashboard":
                dashboard

        })

    except Exception as e:

        print(
            "Dashboard error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to load dashboard.",

            "total_scans": 0,

            "average_risk": 0,

            "critical_risk": 0,

            "high_risk": 0,

            "medium_risk": 0,

            "low_risk": 0,

            "risk_distribution": {},

            "scan_types": {},

            "recent_scans": []

        }), 500


# ============================================================
# EXPLAIN RISK
# ============================================================

@app.route(
    "/api/explain-risk",
    methods=["POST"]
)
def explain_risk():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        score = clamp_score(
            data.get(
                "score",
                0
            )
        )

        context = str(
            data.get(
                "context",
                ""
            )
        )

        prompt = f"""
Explain this cybersecurity risk in simple language.

Risk score:
{score}/100

Context:
{context}

Explain:
- What the score means
- Possible risk
- Why it matters
- Safe defensive actions
"""

        answer, provider = ask_ai(
            prompt
        )

        return jsonify({

            "success": True,

            "score": score,

            "risk_level":
                risk_level(score),

            "explanation":
                answer,

            "provider":
                provider

        })

    except Exception as e:

        print(
            "Risk explanation error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to explain risk."

        }), 500


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

@app.route(
    "/api/security-recommendations",
    methods=["POST"]
)
def security_recommendations():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        context = str(
            data.get(
                "context",
                "General cybersecurity"
            )
        )

        prompt = f"""
Give 8 practical defensive cybersecurity
recommendations for:

{context}

Keep them beginner-friendly.
Do not provide offensive instructions.
"""

        answer, provider = ask_ai(
            prompt
        )

        return jsonify({

            "success": True,

            "recommendations":
                answer,

            "provider":
                provider

        })

    except Exception as e:

        print(
            "Recommendations error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to generate recommendations."

        }), 500


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/api/report/pdf",
    methods=["POST"]
)
def report_pdf():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        target = str(
            data.get(
                "target",
                "Cyber Security Report"
            )
        )

        content = str(
            data.get(
                "content",
                ""
            )
        )

        try:

            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer
            )
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.enums import TA_CENTER

        except ImportError:

            return jsonify({

                "success": False,

                "error":
                    "PDF library is not installed."

            }), 500

        buffer = io.BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            title=target
        )

        styles = getSampleStyleSheet()

        title_style = styles["Title"]

        title_style.alignment = (
            TA_CENTER
        )

        story = []

        story.append(
            Paragraph(
                "Cyber Security AI",
                title_style
            )
        )

        story.append(
            Spacer(
                1,
                20
            )
        )

        story.append(
            Paragraph(
                f"<b>Target:</b> {target}",
                styles["BodyText"]
            )
        )

        story.append(
            Spacer(
                1,
                12
            )
        )

        safe_content = (
            content
            .replace(
                "&",
                "&amp;"
            )
            .replace(
                "<",
                "&lt;"
            )
            .replace(
                ">",
                "&gt;"
            )
            .replace(
                "\n",
                "<br/>"
            )
        )

        story.append(
            Paragraph(
                safe_content,
                styles["BodyText"]
            )
        )

        document.build(
            story
        )

        buffer.seek(0)

        return send_file(

            buffer,

            mimetype="application/pdf",

            as_attachment=True,

            download_name=(
                "cyber-security-report.pdf"
            )

        )

    except Exception as e:

        print(
            "PDF error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to generate PDF."

        }), 500


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify({

            "success": False,

            "error":
                "API endpoint not found."

        }), 404

    return send_from_directory(
        FRONTEND_FOLDER,
        "index.html"
    )


@app.errorhandler(413)
def too_large(error):

    return jsonify({

        "success": False,

        "error":
            "File is too large. Maximum size is 50 MB."

    }), 413


@app.errorhandler(500)
def internal_error(error):

    return jsonify({

        "success": False,

        "error":
            "Internal server error."

    }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "Cyber Security AI"
    )

    print(
        "Server: http://127.0.0.1:5000"
    )

    print("=" * 60)

    print(
        "Gemini:",
        "Available"
        if gemini_clients
        else "Not configured"
    )

    print(
        "Groq:",
        "Available"
        if groq_client
        else "Not configured"
    )

    print(
        "History:",
        "Supabase"
        if supabase_enabled()
        else "Local JSON"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )