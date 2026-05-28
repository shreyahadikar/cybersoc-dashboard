from flask import Flask, request, jsonify, render_template
import joblib
import re
import json
import os
from datetime import datetime
import torch
import torch.nn as nn
from PIL import Image
import torchvision.transforms as transforms
from torchvision import models
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
# =====================================================
# LOAD WEB ATTACK MODEL FILES
# =====================================================

model = joblib.load("ml_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")
label_encoder = joblib.load("encoder.pkl")

# =====================================================
# LOAD NETWORK MODEL FILES
# =====================================================

network_model = joblib.load("network_model.pkl")
network_selector = joblib.load("feature_selector.pkl")
network_encoder = joblib.load("network_encoder.pkl")


# =====================================================
# LOAD EFFICIENTNET MODEL
# =====================================================

deepfake_model = models.efficientnet_b0(weights=None)

# change classifier for 2 classes
deepfake_model.classifier[1] = nn.Linear(
    deepfake_model.classifier[1].in_features,
    2
)

# load weights
deepfake_model.load_state_dict(
    torch.load(
        "deepfake_model.pth",
        map_location=torch.device("cpu")
    )
)


deepfake_model.eval()


# =====================================================
# IMAGE TRANSFORM
# =====================================================

deepfake_transform = transforms.Compose([

    transforms.Resize((224,224)),

    transforms.ToTensor(),

    transforms.Normalize(
        mean=[0.485,0.456,0.406],
        std=[0.229,0.224,0.225]
    )

])

# =====================================================
# LOGIN CONFIG
# =====================================================

VALID_USERNAME = "admin"
VALID_PASSWORD = "admin123"

failed_attempts = {}

BRUTE_FORCE_THRESHOLD = 5

# =====================================================
# LOG FILE
# =====================================================

LOG_FILE = "alerts.json"

# =====================================================
# SAVE ALERT FUNCTION
# =====================================================

def save_alert(alert_data):

    if not os.path.exists(LOG_FILE):

        with open(LOG_FILE, "w") as f:
            json.dump([], f)

    with open(LOG_FILE, "r") as f:
        logs = json.load(f)

    logs.append(alert_data)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

# =====================================================
# BRUTE FORCE DETECTION FUNCTION
# =====================================================

def detect_bruteforce(ip, username, password):

    # Correct Login
    if (
        username == VALID_USERNAME
        and
        password == VALID_PASSWORD
    ):

        failed_attempts[ip] = 0
        return False

    # Wrong Login
    if ip not in failed_attempts:
        failed_attempts[ip] = 0

    failed_attempts[ip] += 1

    # Threshold Reached
    if failed_attempts[ip] >= BRUTE_FORCE_THRESHOLD:
        return True

    return False

# =====================================================
# HOME ROUTE
# =====================================================

@app.route("/")
def home():

    return "Cybersecurity Detection API Running"

# =====================================================
# DASHBOARD PAGE
# =====================================================

@app.route("/dashboard")
def dashboard():

    return render_template("dashboard.html")

@app.route("/deepfake")
def scan_deepfake():

    return render_template("deepfake.html")  

@app.route("/phishing")
def scanPhishing():

    return render_template("phishing.html")      

# =====================================================
# GET ALERTS FOR DASHBOARD
# =====================================================

@app.route("/get_alerts")
def get_alerts():

    if not os.path.exists(LOG_FILE):

        return jsonify([])

    with open(LOG_FILE, "r") as f:
        logs = json.load(f)

    return jsonify(logs)

# =====================================================
# WEB ATTACK DETECTION
# =====================================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.json

        payload = data.get("payload", "")
        page_type = data.get("type", "")

        ip = request.remote_addr

        attack_type = "Normal"
        severity = "LOW"

        # =====================================================
        # BRUTE FORCE DETECTION
        # =====================================================

        if page_type == "login":

            username = data.get("username", "")
            password = data.get("password", "")

            brute_force = detect_bruteforce(
                ip,
                username,
                password
            )

            if brute_force:

                attack_type = "BRUTE_FORCE"
                severity = "CRITICAL"

        # =====================================================
        # XSS PATTERNS
        # =====================================================

        xss_patterns = [

            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\s*\(",
            r"<img[^>]*>",
            r"<svg[^>]*>",
            r"<iframe[^>]*>",
            r"<body[^>]*>",

        ]

        for pattern in xss_patterns:

            if re.search(
                pattern,
                payload,
                re.IGNORECASE | re.DOTALL
            ):

                attack_type = "XSS"
                severity = "HIGH"

        # =====================================================
        # SQL INJECTION PATTERNS
        # =====================================================

        sql_patterns = [

            r"or 1=1",
            r"' or '1'='1",
            r'" or "1"="1',
            r"union select",
            r"--",
            r"drop table",
            r"insert into",
            r"delete from",
            r"update .* set",

        ]

        for pattern in sql_patterns:

            if re.search(
                pattern,
                payload,
                re.IGNORECASE | re.DOTALL
            ):

                attack_type = "SQL_INJECTION"
                severity = "CRITICAL"

        # =====================================================
        # COMMAND INJECTION PATTERNS
        # =====================================================

        cmd_patterns = [

            r"&&",
            r"\|",
            r";",
            r"whoami",
            r"ls",
            r"dir",
            r"cat /etc/passwd",
            r"ping",
            r"netstat",
            r"ipconfig",

        ]

        for pattern in cmd_patterns:

            if re.search(
                pattern,
                payload,
                re.IGNORECASE | re.DOTALL
            ):

                attack_type = "COMMAND_INJECTION"
                severity = "CRITICAL"

        # =====================================================
        # ML MODEL PREDICTION
        # =====================================================

        if attack_type == "Normal":

            payload_vec = vectorizer.transform(
                [payload]
            )

            prediction_encoded = model.predict(
                payload_vec
            )[0]

            prediction = label_encoder.inverse_transform(
                [prediction_encoded]
            )[0]

            attack_type = str(prediction)

        # =====================================================
        # CREATE ALERT
        # =====================================================

        alert = {

            "timestamp": str(datetime.now()),
            "type": "WEB",
            "ip": ip,
            "payload": payload,
            "attack": attack_type,
            "severity": severity

        }

        # =====================================================
        # SAVE ALERT
        # =====================================================

        save_alert(alert)

        print("\nWEB ALERT")
        print(alert)
        print("================================")

        # =====================================================
        # RESPONSE
        # =====================================================

        return jsonify({

            "attack": attack_type,
            "severity": severity

        })

    except Exception as e:

        return jsonify({

            "error": str(e)

        })

# =====================================================
# NETWORK ATTACK DETECTION
# =====================================================

@app.route("/network_predict", methods=["POST"])
def network_predict():

    try:

        data = request.json

        # =====================================================
        # NETWORK FEATURES
        # =====================================================

        packets = float(data.get("packets", 0))
        bytes_count = float(data.get("bytes", 0))
        duration = float(data.get("duration", 0))
        dst_port = float(data.get("dst_port", 80))

        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dst_ip", "")

        prediction = "Normal"

        # =====================================================
        # SAFE TRAFFIC
        # =====================================================

        safe_ports = [443, 53]

        if (
            dst_port in safe_ports
            and packets < 200
            and duration < 300
        ):

            prediction = "Normal"

        # =====================================================
        # SSH BRUTE FORCE
        # =====================================================

        elif (
            dst_port == 22
            and packets > 300
            and duration < 60
        ):

            prediction = "Brute Force"

        # =====================================================
        # FTP BRUTE FORCE
        # =====================================================

        elif (
            dst_port == 21
            and packets > 300
            and duration < 60
        ):

            prediction = "Brute Force"

        # =====================================================
        # HTTP FLOOD / BOT
        # =====================================================

        elif (
            dst_port == 80
            and packets > 1000
        ):

            prediction = "Bot"

        # =====================================================
        # DDOS / FLOOD
        # =====================================================

        elif (
            packets > 5000
            and duration < 20
        ):

            prediction = "Flood Attack"

        # =====================================================
        # PORT SCAN
        # =====================================================

        elif (
            packets < 20
            and duration < 5
            and dst_port not in [80, 443, 53]
        ):

            prediction = "Port Scan"

        # =====================================================
        # INFILTRATION
        # =====================================================

        elif (
            duration > 300
            and bytes_count > 100000
        ):

            prediction = "Infiltration"

        # =====================================================
        # ML MODEL
        # =====================================================

        else:

            features = [[0] * 78]

            features[0][0] = duration
            features[0][1] = packets
            features[0][2] = bytes_count
            features[0][3] = dst_port

            features_selected = network_selector.transform(
                features
            )

            prediction_encoded = network_model.predict(
                features_selected
            )[0]

            prediction = network_encoder.inverse_transform(
                [prediction_encoded]
            )[0]

        # =====================================================
        # REMOVE FALSE POSITIVES
        # =====================================================

        if (
            prediction in [
                "Infiltration",
                "Brute Force"
            ]
            and dst_port == 443
            and packets < 200
        ):

            prediction = "Normal"

        # =====================================================
        # SET SEVERITY
        # =====================================================

        severity = "LOW"

        if prediction in [
            "Brute Force",
            "Flood Attack",
            "Bot"
        ]:

            severity = "CRITICAL"

        elif prediction in [
            "Port Scan",
            "Infiltration"
        ]:

            severity = "HIGH"

        # =====================================================
        # CREATE ALERT
        # =====================================================

        alert = {

            "timestamp": str(datetime.now()),
            "type": "NETWORK",
            "attack": str(prediction),
            "severity": severity,
            "ip": src_ip,
            "payload": f"Port:{dst_port} Packets:{packets}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "packets": packets,
            "bytes": bytes_count,
            "duration": duration

        }

        # =====================================================
        # SAVE ALERT
        # =====================================================

        save_alert(alert)

        print("\nNETWORK ALERT")
        print(alert)
        print("================================")

        # =====================================================
        # RESPONSE
        # =====================================================

        return jsonify(alert)

    except Exception as e:

        print("\nNETWORK ERROR")
        print(str(e))

        return jsonify({

            "error": str(e)

        })

# =====================================================
# DEEPFAKE DETECTION
# =====================================================

@app.route(
    "/deepfake_predict",
    methods=["POST"]
)
def deepfake_predict():

    try:

        if "image" not in request.files:

            return jsonify({

                "error":"No image uploaded"

            })

        file = request.files["image"]

        image = Image.open(file).convert("RGB")

        image = deepfake_transform(image)

        image = image.unsqueeze(0)
        

        with torch.no_grad():

            output = deepfake_model(image)

            prediction = torch.argmax(
                output,
                dim=1
            ).item()

        # =================================================
        # LABELS
        # =================================================

        if prediction == 0:

            result = "FAKE"

            severity = "CRITICAL"

        else:

            result = "REAL"

            severity = "LOW"

        # =================================================
        # ALERT
        # =================================================

        alert = {

            "timestamp": str(datetime.now()),

            "type": "DEEPFAKE",

            "attack": result,

            "severity": severity,

            "ip": request.remote_addr,

            "payload": "Uploaded Image"

        }

        

        print("\nDEEPFAKE ALERT")

        print(alert)

        print("================================")

        return jsonify(alert)

    except Exception as e:

        return jsonify({

            "error": str(e)

        })

# # =====================================================
# # PHISHING URL DETECTION
# # =====================================================

# @app.route("/phishing_detect", methods=["POST"])
# def phishing_detect():

#     try:

#         data = request.json

#         url = data.get("url", "").lower()

#         prediction = "NORMAL"

#         severity = "LOW"

#         # =====================================================
#         # PHISHING KEYWORDS
#         # =====================================================

#         phishing_keywords = [

#             "login",
#             "verify",
#             "secure",
#             "update",
#             "banking",
#             "free",
#             "bonus",
#             "gift",
#             "paypal",
#             "account",
#             "signin",
#             "confirm",
#             "ebay",
#             "amazon",
#             "wallet"

#         ]

#         suspicious_tlds = [

#             ".xyz",
#             ".tk",
#             ".ru",
#             ".cn",
#             ".top",
#             ".gq"

#         ]

#         # =====================================================
#         # DETECTION LOGIC
#         # =====================================================

#         score = 0

#         # HTTPS missing
#         if not url.startswith("https://"):

#             score += 2

#         # IP address in URL
#         if re.search(r"\d+\.\d+\.\d+\.\d+", url):

#             score += 3

#         # Long URL
#         if len(url) > 75:

#             score += 2

#         # Too many hyphens
#         if url.count("-") > 2:

#             score += 2

#         # Suspicious words
#         for word in phishing_keywords:

#             if word in url:

#                 score += 1

#         # Suspicious domains
#         for tld in suspicious_tlds:

#             if tld in url:

#                 score += 3

#         # @ symbol trick
#         if "@" in url:

#             score += 3

#         # =====================================================
#         # FINAL RESULT
#         # =====================================================

#         if score >= 6:

#             prediction = "PHISHING"

#             severity = "CRITICAL"

#         elif score >= 3:

#             prediction = "SUSPICIOUS"

#             severity = "HIGH"

#         # =====================================================
#         # SAVE ALERT
#         # =====================================================

#         alert = {

#             "timestamp": str(datetime.now()),

#             "type": "PHISHING",

#             "ip": request.remote_addr,

#             "payload": url,

#             "attack": prediction,

#             "severity": severity

#         }

#         save_alert(alert)

#         print("\nPHISHING ALERT")
#         print(alert)
#         print("================================")

#         return jsonify(alert)

#     except Exception as e:

#         return jsonify({

#             "error": str(e)

#         })




# =====================================================
# PHISHING EMAIL + URL DETECTION
# =====================================================

@app.route(
    "/phishing_predict",
    methods=["POST"]
)
def phishing_predict():

    try:

        data = request.json

        text = data.get(
            "input",
            ""
        ).strip().lower()

        result = "SAFE"

        severity = "LOW"

        # =====================================================
        # PHISHING EMAIL KEYWORDS
        # =====================================================

        phishing_keywords = [

            "verify your account",
            "click below",
            "login immediately",
            "password expired",
            "bank account",
            "account suspended",
            "urgent action",
            "confirm identity",
            "security alert",
            "reset password",
            "free reward",
            "gift card",
            "crypto wallet",
            "paypal",
            "limited offer",
            "invoice attached",
            "update payment",
            "claim now",
            "your account will be closed",
            "unusual activity",
            "login to continue",
            "confirm your password"

        ]

        # =====================================================
        # SUSPICIOUS DOMAIN PATTERNS
        # =====================================================

        suspicious_patterns = [

            r"bit\.ly",
            r"tinyurl",
            r"goo\.gl",
            r"t\.co",

            r"go0gle",
            r"paypa1",
            r"amaz0n",
            r"micr0soft",

            r"secure-login",
            r"verify-account",
            r"free-gift",
            r"bonus-reward"

        ]

        # =====================================================
        # TRUSTED DOMAINS
        # =====================================================

        trusted_domains = [

            "google.com",
            "github.com",
            "microsoft.com",
            "amazon.com",
            "paypal.com",
            "openai.com",
            "youtube.com",
            "facebook.com",
            "instagram.com",
            "linkedin.com",
            "twitter.com",
            "x.com"

        ]

        # =====================================================
        # EXTRACT DOMAIN
        # =====================================================

        domain = text

        domain_match = re.search(

            r"https?://([^/]+)",
            text

        )

        if domain_match:

            domain = domain_match.group(1)

        domain = domain.replace(
            "www.",
            ""
        )

        # =====================================================
        # CHECK TRUSTED DOMAIN
        # =====================================================

        trusted = False

        for safe_domain in trusted_domains:

            if domain == safe_domain:

                trusted = True
                break

        # =====================================================
        # CHECK PHISHING KEYWORDS
        # =====================================================

        keyword_hits = 0

        for keyword in phishing_keywords:

            if keyword in text:

                keyword_hits += 1

        # =====================================================
        # CHECK SUSPICIOUS PATTERNS
        # =====================================================

        suspicious_hits = 0

        for pattern in suspicious_patterns:

            if re.search(

                pattern,
                text,
                re.IGNORECASE

            ):

                suspicious_hits += 1

        # =====================================================
        # DETECTION LOGIC
        # =====================================================

        # Safe trusted domains
        if trusted:

            result = "SAFE"

            severity = "LOW"

        # Strong phishing detection
        elif (

            suspicious_hits >= 1
            and
            keyword_hits >= 1

        ):

            result = "PHISHING DETECTED"

            severity = "CRITICAL"

        # Suspicious email content
        elif keyword_hits >= 2:

            result = "SUSPICIOUS EMAIL"

            severity = "HIGH"

        # Suspicious fake URLs
        elif suspicious_hits >= 1:

            result = "SUSPICIOUS LINK"

            severity = "HIGH"

        else:

            result = "SAFE"

            severity = "LOW"

        # =====================================================
        # SAVE ALERT
        # =====================================================

        alert = {

            "timestamp": str(datetime.now()),

            "type": "PHISHING",

            "attack": result,

            "severity": severity,

            "ip": request.remote_addr,

            "payload": text

        }

        

        print("\nPHISHING ALERT")

        print(alert)

        print("================================")

        # =====================================================
        # RESPONSE
        # =====================================================

        return jsonify({

            "result": result,

            "severity": severity

        })

    except Exception as e:

        return jsonify({

            "error": str(e)

        })

# =====================================================
# RUN SERVER
# =====================================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port
    )