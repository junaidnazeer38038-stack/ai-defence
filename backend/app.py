from flask import Flask, send_from_directory, request, jsonify, send_file, g
from flask_cors import CORS
from google import genai
from groq import Groq
from dotenv import load_dotenv
from backend.url_scanner import scan_url

import os
import hashlib
import re
import socket
import ipaddress
import json
import io
import uuid
from datetime import datetime


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

FRONTEND_FOLDER = os.path.join(
    BASE_DIR,
    "frontend"
)

HISTORY_FILE = os.path.join(
    BASE_DIR,
    "history.json"
)


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
# API KEYS
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
# SECURITY SYSTEM PROMPT
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
# USER HISTORY
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


def load_history():

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


def save_history_entry(entry):

    user_id = get_user_id()

    all_history = load_all_history()

    if user_id not in all_history:
        all_history[user_id] = []

    all_history[user_id].insert(
        0,
        entry
    )

    # Maximum 100 scans per browser
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


def clear_history():

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

    score = clamp_score(score)

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
# GEMINI
# ============================================================

def ask_gemini(prompt):

    if not gemini_clients:

        print(
            "Gemini is not configured."
        )

        return None

    full_prompt = (
        SYSTEM_PROMPT
        + "\n\nUser request:\n"
        + prompt
    )

    for index, client in enumerate(
        gemini_clients,
        start=1
    ):

        try:

            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=full_prompt
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


# ============================================================
# GROQ
# ============================================================

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


# ============================================================
# AI FALLBACK
# ============================================================

def ask_ai(prompt):

    # Groq first
    answer = ask_groq(
        prompt
    )

    if answer:

        return (
            answer,
            "Groq"
        )

    # Gemini second
    answer = ask_gemini(
        prompt
    )

    if answer:

        return (
            answer,
            "Gemini"
        )

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
def status():

    return jsonify({

        "status": "online",

        "service":
            "Cyber Security AI",

        "ai_available":
            bool(
                gemini_clients
                or groq_client
            ),

        "gemini_available":
            bool(
                gemini_clients
            ),

        "groq_available":
            bool(
                groq_client
            ),

        "features": 9,

        "time":
            now()
    })


# ============================================================
# 1. AI CHAT
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
                "reply":
                    "Please enter a message.",
                "provider":
                    "System"
            }), 400

        answer, provider = ask_ai(
            message
        )

        return jsonify({

            "success": True,

            "reply":
                answer,

            "provider":
                provider
        })

    except Exception as e:

        print(
            "Chat error:",
            e
        )

        return jsonify({

            "success": False,

            "reply":
                "Unable to process the request.",

            "provider":
                "System"

        }), 500


# ============================================================
# 2. URL SCANNER
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
                "error":
                    "Please enter a URL."
            }), 400

        result = scan_url(
            url
        )

        if not isinstance(
            result,
            dict
        ):

            result = {
                "result":
                    str(result)
            }

        score = result.get(
            "risk_score"
        )

        if score is None:

            status_value = str(
                result.get(
                    "status",
                    ""
                )
            ).lower()

            suspicious = str(
                result.get(
                    "suspicious",
                    ""
                )
            ).lower()

            score = 10

            if (
                "malicious" in status_value
                or
                "danger" in status_value
                or
                suspicious == "true"
            ):

                score = 85

            elif (
                "suspicious" in status_value
                or
                "warning" in status_value
            ):

                score = 60

        score = clamp_score(
            score
        )

        result["risk_score"] = score

        result["risk_level"] = risk_level(
            score
        )

        history_entry = add_history(

            "URL Scan",

            url,

            score,

            result,

            "URL safety analysis"
        )

        return jsonify({

            "success": True,

            "result":
                result,

            "risk_score":
                score,

            "risk_level":
                risk_level(score),

            "history_id":
                history_entry["id"]
        })

    except Exception as e:

        print(
            "URL scan error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to scan the URL."

        }), 500


# ============================================================
# 3. FILE SCANNER
# ============================================================

@app.route(
    "/api/scan-file",
    methods=["POST"]
)
def scan_file():

    try:

        if "file" not in request.files:

            return jsonify({

                "success": False,

                "error":
                    "No file uploaded."

            }), 400

        file = request.files[
            "file"
        ]

        if not file.filename:

            return jsonify({

                "success": False,

                "error":
                    "Please select a file."

            }), 400

        filename = file.filename

        content = file.read()

        file_size = len(
            content
        )

        sha256_hash = hashlib.sha256(
            content
        ).hexdigest()

        extension = os.path.splitext(
            filename
        )[1].lower()

        dangerous_extensions = {

            ".exe",
            ".bat",
            ".cmd",
            ".scr",
            ".msi",
            ".vbs",
            ".js",
            ".ps1",
            ".jar",
            ".dll"
        }

        suspicious_extension = (
            extension
            in dangerous_extensions
        )

        score = (
            65
            if suspicious_extension
            else 5
        )

        result = {

            "filename":
                filename,

            "extension":
                extension or "none",

            "size_bytes":
                file_size,

            "sha256":
                sha256_hash,

            "suspicious_extension":
                suspicious_extension,

            "risk_score":
                score,

            "risk_level":
                risk_level(score),

            "message": (

                "Potentially risky file type. "
                "Do not open it unless you trust the source."

                if suspicious_extension

                else

                "No obvious file-type warning was detected."
            )
        }

        # Only metadata/hash is saved.
        history_result = {

            "filename":
                filename,

            "extension":
                extension or "none",

            "size_bytes":
                file_size,

            "sha256":
                sha256_hash,

            "suspicious_extension":
                suspicious_extension
        }

        history_entry = add_history(

            "File Scan",

            filename,

            score,

            history_result,

            "File metadata and hash analysis"
        )

        return jsonify({

            "success": True,

            "result":
                result,

            "risk_score":
                score,

            "risk_level":
                risk_level(score),

            "history_id":
                history_entry["id"]
        })

    except Exception as e:

        print(
            "File scan error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to scan the file."

        }), 500


# ============================================================
# 4. PHISHING DETECTOR
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
                "message",
                data.get(
                    "text",
                    ""
                )
            )
        ).strip()

        if not text:

            return jsonify({

                "success": False,

                "error":
                    "Please enter a message or email."

            }), 400

        text_lower = text.lower()

        indicators = []

        phishing_words = [

            "urgent",
            "verify your account",
            "verify account",
            "click here",
            "password",
            "login",
            "suspended",
            "winner",
            "prize",
            "bank",
            "otp",
            "confirm your account",
            "limited time",
            "security alert"
        ]

        for word in phishing_words:

            if word in text_lower:

                indicators.append(
                    word
                )

        # Correct URL detection
        url_matches = re.findall(
            r"https?://[^\s]+|www\.[^\s]+",
            text,
            flags=re.IGNORECASE
        )

        score = min(

            95,

            (
                len(indicators)
                * 10
            )
            +
            (
                len(url_matches)
                * 20
            )
        )

        if len(indicators) >= 4:

            score = max(
                score,
                70
            )

        result = {

            "risk_score":
                score,

            "risk_level":
                risk_level(score),

            "phishing_indicators":
                indicators,

            "urls_found":
                url_matches,

            "indicator_count":
                len(indicators),

            "recommendation": (

                "Do not click links or provide credentials. "
                "Verify the sender using an official channel."

                if score >= 50

                else

                "No strong phishing pattern was detected, "
                "but remain cautious."
            )
        }

        history_entry = add_history(

            "Phishing Detection",

            "Message Analysis",

            score,

            result,

            "Phishing indicator analysis"
        )

        return jsonify({

            "success": True,

            "result":
                result,

            "risk_score":
                score,

            "risk_level":
                risk_level(score),

            "history_id":
                history_entry["id"]
        })

    except Exception as e:

        print(
            "Phishing detection error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to analyze the message."

        }), 500


# ============================================================
# 5. PASSWORD CHECKER
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

                "error":
                    "Please enter a password."

            }), 400

        common_passwords = {

            "password",
            "123456",
            "12345678",
            "qwerty",
            "admin",
            "password123",
            "123456789"
        }

        checks = {

            "length_8_plus":
                len(password) >= 8,

            "length_12_plus":
                len(password) >= 12,

            "uppercase":
                bool(
                    re.search(
                        r"[A-Z]",
                        password
                    )
                ),

            "lowercase":
                bool(
                    re.search(
                        r"[a-z]",
                        password
                    )
                ),

            "number":
                bool(
                    re.search(
                        r"\d",
                        password
                    )
                ),

            "special":
                bool(
                    re.search(
                        r"[^A-Za-z0-9]",
                        password
                    )
                ),

            "common_password":
                password.lower()
                in common_passwords
        }

        points = 0

        for key in [

            "length_8_plus",
            "length_12_plus",
            "uppercase",
            "lowercase",
            "number",
            "special"

        ]:

            if checks[key]:
                points += 1

        if checks[
            "common_password"
        ]:

            points = 0

        security_score = round(

            (
                points / 6
            ) * 100
        )

        if checks[
            "common_password"
        ]:

            security_score = 5

        risk_score = (
            100
            - security_score
        )

        result = {

            "length":
                len(password),

            "checks":
                checks,

            "strength_points":
                points,

            "risk_score":
                risk_score,

            "security_score":
                security_score,

            "risk_level":
                risk_level(
                    risk_score
                ),

            "message": (

                "Use a longer, unique password "
                "with multiple character types."

                if security_score < 70

                else

                "Password has a stronger structure. "
                "Use a unique password for every account."
            )
        }

        # IMPORTANT:
        # Passwords are NEVER saved in history.
        # No actual password or password metadata is stored.

        return jsonify({

            "success": True,

            "result":
                result,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level(
                    risk_score
                ),

            "security_score":
                security_score
        })

    except Exception as e:

        print(
            "Password checker error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to check the password."

        }), 500


# ============================================================
# 6. IP / DOMAIN INFO
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
                ""
            )
        ).strip()

        if not target:

            return jsonify({

                "success": False,

                "error":
                    "Please enter an IP address or domain."

            }), 400

        target_clean = re.sub(

            r"^https?://",

            "",

            target,

            flags=re.IGNORECASE
        )

        target_clean = (
            target_clean
            .split("/")[0]
            .split(":")[0]
        )

        info = {

            "target":
                target,

            "normalized_target":
                target_clean,

            "timestamp":
                now()
        }

        score = 10

        try:

            ip_obj = ipaddress.ip_address(
                target_clean
            )

            info["type"] = "IP Address"

            info["ip_version"] = ip_obj.version

            info["is_private"] = ip_obj.is_private

            info["is_global"] = ip_obj.is_global

            info["is_loopback"] = ip_obj.is_loopback

            if (
                ip_obj.is_private
                or
                ip_obj.is_loopback
            ):

                score = 5

        except ValueError:

            info["type"] = "Domain"

            try:

                resolved_ip = socket.gethostbyname(
                    target_clean
                )

                info["resolved_ip"] = resolved_ip

                try:

                    reverse_name = socket.gethostbyaddr(
                        resolved_ip
                    )[0]

                    info["reverse_dns"] = reverse_name

                except Exception:

                    info["reverse_dns"] = None

            except Exception:

                info["resolved_ip"] = None

                info["reverse_dns"] = None

                score = 30

        info["risk_score"] = score

        info["risk_level"] = risk_level(
            score
        )

        history_entry = add_history(

            "IP / Domain Info",

            target_clean,

            score,

            info,

            "Basic DNS/IP information lookup"
        )

        return jsonify({

            "success": True,

            "result":
                info,

            "risk_score":
                score,

            "risk_level":
                risk_level(score),

            "history_id":
                history_entry["id"]
        })

    except Exception as e:

        print(
            "IP/domain error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to retrieve information."

        }), 500


# ============================================================
# 7. SECURITY REPORT
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

        report_data = data.get(
            "data",
            data
        )

        prompt = f"""
Create a professional defensive cybersecurity report
from the following analysis data.

Data:

{json.dumps(
    report_data,
    indent=2,
    default=str
)}

Include:

- Executive Summary
- Findings
- Risk Level
- Why the finding may be risky
- Recommended Defensive Actions
- Prevention Tips

Do not provide offensive instructions.
"""

        report, provider = ask_ai(
            prompt
        )

        return jsonify({

            "success": True,

            "report":
                report,

            "provider":
                provider
        })

    except Exception as e:

        print(
            "Security report error:",
            e
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to generate the security report."

        }), 500


# ============================================================
# 8. THREAT ALERTS
# ============================================================

@app.route(
    "/api/threat-alerts",
    methods=["GET"]
)
def threat_alerts():

    alerts = [

        {
            "title":
                "Phishing Protection",

            "severity":
                "High",

            "message":
                "Be careful with unexpected login "
                "and verification links.",

            "action":
                "Verify the sender through an official channel."
        },

        {
            "title":
                "Password Safety",

            "severity":
                "Medium",

            "message":
                "Avoid reusing passwords across different accounts.",

            "action":
                "Use unique passwords for important accounts."
        },

        {
            "title":
                "File Safety",

            "severity":
                "Medium",

            "message":
                "Unexpected executable files can be risky.",

            "action":
                "Only open files from trusted sources."
        },

        {
            "title":
                "Public Wi-Fi",

            "severity":
                "Medium",

            "message":
                "Public networks can expose traffic "
                "to additional risks.",

            "action":
                "Avoid sensitive activity on untrusted networks."
        }
    ]

    return jsonify({

        "success":
            True,

        "alerts":
            alerts,

        "updated":
            now()
    })


# ============================================================
# 9. SECURITY DASHBOARD
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

        if total_scans:

            average_score = round(

                sum(

                    clamp_score(
                        item.get(
                            "risk_score",
                            0
                        )
                    )

                    for item in history

                ) / total_scans
            )

        else:

            average_score = 0

        high_risk = sum(

            1

            for item in history

            if clamp_score(
                item.get(
                    "risk_score",
                    0
                )
            ) >= 60
        )

        medium_risk = sum(

            1

            for item in history

            if 30 <= clamp_score(
                item.get(
                    "risk_score",
                    0
                )
            ) < 60
        )

        low_risk = sum(

            1

            for item in history

            if clamp_score(
                item.get(
                    "risk_score",
                    0
                )
            ) < 30
        )

        type_counts = {}

        for item in history:

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

        dashboard = {

            "total_scans":
                total_scans,

            "average_risk_score":
                average_score,

            "overall_risk_level":
                risk_level(
                    average_score
                ),

            "high_risk_scans":
                high_risk,

            "medium_risk_scans":
                medium_risk,

            "low_risk_scans":
                low_risk,

            "scan_types":
                type_counts,

            "recent_scans":
                history[:10],

            "system_status":
                "Online",

            "ai_status": (

                "Available"

                if (
                    gemini_clients
                    or
                    groq_client
                )

                else

                "Unavailable"
            ),

            "ai_providers": {

                "gemini":
                    bool(
                        gemini_clients
                    ),

                "groq":
                    bool(
                        groq_client
                    )
            },

            "security_tips": [

                "Never share passwords or OTP codes.",

                "Verify unexpected links before opening them.",

                "Keep your operating system and applications updated.",

                "Use unique passwords for important accounts.",

                "Back up important files regularly."
            ]
        }

        # Return both formats:
        # direct fields for the current frontend
        # and dashboard object for compatibility.

        return jsonify({

            "success": True,

            "total_scans":
                total_scans,

            "average_risk":
                average_score,

            "average_risk_score":
                average_score,

            "overall_risk_level":
                dashboard[
                    "overall_risk_level"
                ],

            "high_risk":
                high_risk,

            "high_risk_scans":
                high_risk,

            "medium_risk":
                medium_risk,

            "medium_risk_scans":
                medium_risk,

            "low_risk":
                low_risk,

            "low_risk_scans":
                low_risk,

            "scan_types":
                type_counts,

            "recent_scans":
                history[:10],

            "system_status":
                "Online",

            "ai_status":
                dashboard[
                    "ai_status"
                ],

            "ai_providers":
                dashboard[
                    "ai_providers"
                ],

            "security_tips":
                dashboard[
                    "security_tips"
                ],

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
                "Unable to load dashboard."

        }), 500


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

            "success":
                True,

            "count":
                len(history),

            "history":
                history

        })

    except Exception as e:

        print(
            "Get history error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                "Unable to load history.",

            "history":
                []

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

                "success":
                    True,

                "message":
                    "Scan history cleared.",

                "history":
                    []

            })

        return jsonify({

            "success":
                False,

            "error":
                "Unable to clear history."

        }), 500

    except Exception as e:

        print(
            "Clear history error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                "Unable to clear history."

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

        result_data = data.get(

            "finding",

            data.get(
                "data",
                data
            )
        )

        prompt = f"""
Explain the following cybersecurity finding
to a beginner.

Finding:

{json.dumps(
    result_data,
    indent=2,
    default=str
)}

Give:

1. What was detected
2. Why it may be risky
3. What a normal user should do
4. What the user should avoid

Keep the answer defensive and easy to understand.
"""

        explanation, provider = ask_ai(
            prompt
        )

        return jsonify({

            "success":
                True,

            "explanation":
                explanation,

            "provider":
                provider
        })

    except Exception as e:

        print(
            "Risk explanation error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                "Unable to explain the risk."

        }), 500


# ============================================================
# SMART RECOMMENDATIONS
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

        result_data = data.get(

            "finding",

            data.get(
                "data",
                data
            )
        )

        prompt = f"""
Create smart defensive cybersecurity recommendations
based on this scan:

{json.dumps(
    result_data,
    indent=2,
    default=str
)}

Return:

- Immediate Actions
- Recommended Actions
- Prevention Tips

Keep the advice practical for a normal user.

Do not provide offensive instructions.
"""

        recommendations, provider = ask_ai(
            prompt
        )

        return jsonify({

            "success":
                True,

            "recommendations":
                recommendations,

            "provider":
                provider
        })

    except Exception as e:

        print(
            "Recommendations error:",
            e
        )

        return jsonify({

            "success":
                False,

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
def generate_pdf_report():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        report_title = data.get(
            "title",
            "Cyber Security AI - Security Report"
        )

        report_text = data.get(
            "report",
            ""
        )

        scan_type = data.get(
            "scan_type",
            "Security Analysis"
        )

        target = data.get(
            "target",
            "Not specified"
        )

        score = clamp_score(
            data.get(
                "risk_score",
                0
            )
        )

        level = risk_level(
            score
        )

        try:

            from reportlab.lib.pagesizes import A4

            from reportlab.lib.styles import (
                getSampleStyleSheet
            )

            from reportlab.lib.enums import (
                TA_CENTER
            )

            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle
            )

            from reportlab.lib import colors

        except ImportError:

            return jsonify({

                "success":
                    False,

                "error":
                    "PDF library is not installed."

            }), 500

        buffer = io.BytesIO()

        document = SimpleDocTemplate(

            buffer,

            pagesize=A4,

            rightMargin=40,

            leftMargin=40,

            topMargin=40,

            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        title_style = styles[
            "Title"
        ]

        title_style.alignment = (
            TA_CENTER
        )

        normal_style = styles[
            "BodyText"
        ]

        story = []

        story.append(

            Paragraph(
                report_title,
                title_style
            )
        )

        story.append(

            Spacer(
                1,
                20
            )
        )

        table_data = [

            [
                "Report Type",
                scan_type
            ],

            [
                "Target",
                str(target)
            ],

            [
                "Risk Score",
                f"{score}/100"
            ],

            [
                "Risk Level",
                level
            ],

            [
                "Generated",
                now()
            ]
        ]

        table = Table(

            table_data,

            colWidths=[
                120,
                350
            ]
        )

        table.setStyle(

            TableStyle([

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    8
                )

            ])
        )

        story.append(
            table
        )

        story.append(

            Spacer(
                1,
                20
            )
        )

        story.append(

            Paragraph(
                "<b>Security Analysis</b>",
                styles["Heading2"]
            )
        )

        story.append(

            Spacer(
                1,
                8
            )
        )

        clean_report = (

            str(report_text)

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
                clean_report,
                normal_style
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
                "<b>Defensive Notice</b>",
                styles["Heading2"]
            )
        )

        story.append(

            Paragraph(

                "This report is intended for defensive "
                "and educational cybersecurity purposes. "
                "A scan result does not guarantee that a "
                "system, file, or website is completely "
                "safe or malicious.",

                normal_style
            )
        )

        document.build(
            story
        )

        buffer.seek(0)

        filename = (

            "cyber_security_report_"

            + datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            + ".pdf"
        )

        return send_file(

            buffer,

            mimetype="application/pdf",

            as_attachment=True,

            download_name=filename
        )

    except Exception as e:

        print(
            "PDF report error:",
            e
        )

        return jsonify({

            "success":
                False,

            "error":
                "Unable to create PDF report."

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

            "success":
                False,

            "error":
                "API endpoint not found.",

            "path":
                request.path

        }), 404

    return error


@app.errorhandler(413)
def file_too_large(error):

    return jsonify({

        "success":
            False,

        "error":
            "File is too large. Maximum size is 50 MB."

    }), 413


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print(
        "=" * 60
    )

    print(
        "Cyber Security AI"
    )

    print(
        "Server: http://127.0.0.1:5000"
    )

    print(
        "=" * 60
    )

    print(
        "Gemini:",
        "Available"
        if gemini_clients
        else
        "Not configured"
    )

    print(
        "Groq:",
        "Available"
        if groq_client
        else
        "Not configured"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )