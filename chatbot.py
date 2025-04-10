import sqlite3
import re
import os
import requests
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import time
import mimetypes
import hashlib
import json
from flask_cors import CORS
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = "my-secure-key-123"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
CORS(app, origins=["http://localhost:8000"], supports_credentials=True)

# ================== ML MODELS ==================
class SecurityML:
    def __init__(self):
        self.models_dir = "ml_models"
        os.makedirs(self.models_dir, exist_ok=True)
        self.load_models()
        
    def load_models(self):
        try:
            self.anomaly_model = joblib.load(f"{self.models_dir}/anomaly_model.joblib")
            self.vectorizer = joblib.load(f"{self.models_dir}/vectorizer.joblib")
            self.behavior_model = joblib.load(f"{self.models_dir}/behavior_model.joblib")
        except:
            self.train_models()
    
    def train_models(self):
        # Anomaly detection model
        normal_requests = ["GET /", "POST /login", "GET /styles.css"]
        self.vectorizer = TfidfVectorizer()
        X = self.vectorizer.fit_transform(normal_requests)
        self.anomaly_model = IsolationForest(n_estimators=100)
        self.anomaly_model.fit(X)
        
        # Behavior model
        X_behavior = np.array([[10,0.5], [20,0.8], [5,0.2]])
        y_behavior = np.array([0, 1, 0])
        self.behavior_model = RandomForestClassifier()
        self.behavior_model.fit(X_behavior, y_behavior)
        
        joblib.dump(self.anomaly_model, f"{self.models_dir}/anomaly_model.joblib")
        joblib.dump(self.vectorizer, f"{self.models_dir}/vectorizer.joblib")
        joblib.dump(self.behavior_model, f"{self.models_dir}/behavior_model.joblib")

ml_engine = SecurityML()

# ================== DATABASE ==================
def init_db():
    conn = sqlite3.connect("attacks.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY,
            attack_type TEXT,
            source_ip TEXT,
            timestamp TEXT,
            details TEXT,
            confidence REAL,
            location TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ================== SECURITY CONFIG ==================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"
REQUEST_LIMIT = 10
TIME_WINDOW = 60
BLOCK_DURATION = 300
DDOS_THRESHOLD = 10
DDOS_WINDOW_SECONDS = 60
SQL_BLOCK_DURATION = 24 * 60 * 60
VT_API_KEY = "fdc4b43d9a29913efe5b8fabbef445bf6d2a59938ffff81beecba334901f634e"

request_counts = defaultdict(list)
blocked_ips = defaultdict(float)
sql_blocked_ips = defaultdict(float)
request_tracker_ddos = defaultdict(list)

# ================== HELPER FUNCTIONS ==================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('serve_login'))
        return f(*args, **kwargs)
    return decorated_function

def log_attack(attack_type, source_ip, details=None, confidence=None):
    conn = sqlite3.connect("attacks.db")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO attacks (attack_type, source_ip, timestamp, details, confidence)
        VALUES (?, ?, ?, ?, ?)
    """, (attack_type, source_ip, timestamp, details, confidence))
    conn.commit()
    conn.close()

def detect_ddos(source_ip):
    current_time = time.time()
    request_tracker_ddos[source_ip].append(current_time)
    request_tracker_ddos[source_ip] = [t for t in request_tracker_ddos[source_ip] if current_time - t < DDOS_WINDOW_SECONDS]
    request_count = len(request_tracker_ddos[source_ip])
    if request_count > DDOS_THRESHOLD:
        return True, f"Request rate: {request_count} requests in {DDOS_WINDOW_SECONDS} seconds"
    return False, None

def detect_malware(request_data=None, file_content=None, filename=None):
    if request_data:
        request_data = request_data.lower()
        sql_patterns = [
            r"union.*select", r"--", r"or\s+1\s*=\s*1", r";\s*drop",
            r"'\s*or\s*''='", r"select.*from"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, request_data):
                return "SQL Injection", None

    if file_content is not None:
        if not file_content:
            return "Invalid File", f"File {filename} is empty"

        if filename:
            mime_type, _ = mimetypes.guess_type(filename)
            file_type = mime_type if mime_type else "Unknown"
        else:
            file_type = "Unknown"

        file_hash = hashlib.md5(file_content).hexdigest()
        vt_url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {"apikey": VT_API_KEY, "resource": file_hash}
        
        try:
            response = requests.get(vt_url, params=params)
            response.raise_for_status()
            vt_result = response.json()

            if vt_result.get("response_code") == 1:
                positives = vt_result.get("positives", 0)
                if positives > 0:
                    return "Malware", f"VirusTotal detected {positives} positives"
        except requests.RequestException:
            pass

        malicious_signatures = [b'\xE8\x00\x00\x00\x00', b'\x90\x90\x90\x90\x90']
        for sig in malicious_signatures:
            if sig in file_content:
                return "Malware", f"Detected malicious signature"

        suspicious_extensions = [".exe", ".bat", ".cmd", ".vbs", ".js"]
        if filename and any(filename.lower().endswith(ext) for ext in suspicious_extensions):
            return "Malware", f"Suspicious file extension"

    return None, None

# ================== ROUTES ==================
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/login.html')
def serve_login():
    return send_from_directory('.', 'login.html')

@app.route('/chatbot.html')
@login_required
def serve_chatbot():
    return send_from_directory('.', 'chatbot.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get("username", "")
        password = data.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return jsonify({"status": "success", "message": "Logged in successfully"}), 200
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    return jsonify({"status": "success", "message": "Logged out"}), 200

@app.route('/analyze', methods=['POST'])
def analyze_request():
    try:
        data = request.json
        source_ip = request.remote_addr
        request_data = data.get("request_data", "")
        
        # ML Anomaly Detection
        if ml_engine.vectorizer and ml_engine.anomaly_model:
            X = ml_engine.vectorizer.transform([request_data])
            pred = ml_engine.anomaly_model.predict(X)
            if pred[0] == -1:
                log_attack("ML Anomaly", source_ip, "Anomalous request pattern", 0.85)
                return jsonify({
                    "status": "attack_detected",
                    "type": "Anomalous Pattern",
                    "details": "ML model detected suspicious request"
                }), 200

        # Existing detection logic
        attack_type, details = detect_malware(request_data=request_data)
        if attack_type == "SQL Injection":
            sql_blocked_ips[source_ip] = time.time() + SQL_BLOCK_DURATION
            log_attack(attack_type, source_ip, details, 0.95)
            return jsonify({
                "status": "blocked",
                "message": "Malicious input detected"
            }), 403

        return jsonify({"status": "clean"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file"}), 400
            
        file = request.files['file']
        file_content = file.read()
        
        # ML File Analysis
        if ml_engine.behavior_model:
            features = np.array([[
                len(file_content),
                ml_engine.calculate_entropy(file_content),
                int(ml_engine.detect_pe_header(file_content)),
                int(ml_engine.detect_script_tags(file_content))
            ]])
            pred = ml_engine.behavior_model.predict(features)
            if pred[0] == 1:
                log_attack("ML Malware", request.remote_addr, "Suspicious file features", 0.9)
                return jsonify({
                    "status": "blocked",
                    "message": "File blocked by ML analysis"
                }), 403

        # Existing malware check
        attack_type, details = detect_malware(file_content=file_content, filename=file.filename)
        if attack_type:
            log_attack(attack_type, request.remote_addr, details, 0.95)
            return jsonify({
                "status": "blocked",
                "message": "Malicious file detected"
            }), 403

        return jsonify({"status": "clean"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/report', methods=['GET'])
@login_required
def get_report():
    conn = sqlite3.connect("attacks.db")
    attacks = conn.execute("""
        SELECT * FROM attacks 
        ORDER BY timestamp DESC 
        LIMIT 10
    """).fetchall()
    conn.close()
    
    return jsonify({
        "attacks": [{
            "id": a[0], "type": a[1], 
            "ip": a[2], "time": a[3],
            "details": a[4], "confidence": a[5]
        } for a in attacks]
    })

@app.route('/blocked-ips', methods=['GET'])
@login_required
def get_blocked_ips():
    current_time = time.time()
    blocked = [
        {"ip": ip, "reason": "Brute Force", "expires": expires}
        for ip, expires in blocked_ips.items() if expires > current_time
    ] + [
        {"ip": ip, "reason": "SQL Injection", "expires": expires}
        for ip, expires in sql_blocked_ips.items() if expires > current_time
    ]
    return jsonify({"status": "success", "blocked_ips": blocked})

@app.route('/unblock-ip', methods=['POST'])
@login_required
def unblock_ip():
    ip_to_unblock = request.json.get("ip")
    if ip_to_unblock in blocked_ips:
        del blocked_ips[ip_to_unblock]
    if ip_to_unblock in sql_blocked_ips:
        del sql_blocked_ips[ip_to_unblock]
    return jsonify({"status": "success", "message": f"Unblocked {ip_to_unblock}"})

# ================== VISUALIZATION ROUTES ==================
@app.route('/api/attack-heatmap')
@login_required
def attack_heatmap():
    conn = sqlite3.connect("attacks.db")
    attacks = conn.execute("""
        SELECT source_ip, COUNT(*) as count 
        FROM attacks 
        WHERE timestamp > datetime('now', '-1 day')
        GROUP BY source_ip
    """).fetchall()
    conn.close()
    
    geo_data = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {"count": count},
                "geometry": {
                    "type": "Point",
                    "coordinates": [float(ip.split('.')[0]), float(ip.split('.')[1])]
                }
            } for ip, count in attacks
        ]
    }
    return jsonify(geo_data)

@app.route('/api/attack-trends')
@login_required
def attack_trends():
    conn = sqlite3.connect("attacks.db")
    trends = conn.execute("""
        SELECT strftime('%H', timestamp) as hour,
               SUM(CASE WHEN attack_type LIKE '%SQL%' THEN 1 ELSE 0 END) as sqli,
               SUM(CASE WHEN attack_type LIKE '%XSS%' THEN 1 ELSE 0 END) as xss
        FROM attacks
        WHERE timestamp > datetime('now', '-1 day')
        GROUP BY hour
    """).fetchall()
    conn.close()
    
    return jsonify({
        "labels": [f"{hour}:00" for hour, _, _ in trends],
        "sqli": [sqli for _, sqli, _ in trends],
        "xss": [xss for _, _, xss in trends]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)x