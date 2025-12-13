import sqlite3
import subprocess
import os
import datetime
import math
import requests # Requires: sudo apt install python3-requests
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# --- CONFIGURATION: YOUR API URL ---
EMAIL_API_URL = "https://formspree.io/f/xgvgrzzq"
# -----------------------------------

BLOCKED_IPS = {}

class AIEngine:
    @staticmethod
    def calculate_entropy(text):
        # AI Logic: Calculate randomness (High randomness = Exploit code)
        if not text: return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def analyze_threat(text):
        # Heuristic Analysis to determine "Threat Score"
        score = 0
        confidence = 0
        
        # Feature 1: Length Anomaly (Buffer Overflows are long)
        if len(text) > 50: score += 40
        
        # Feature 2: High Entropy (Shellcode is random)
        if AIEngine.calculate_entropy(text) > 3.5: score += 30
        
        # Feature 3: Keyword Heuristics (SQLi/XSS patterns)
        keywords = ["SELECT", "UNION", "OR", "AND", "SCRIPT", "ALERT", "DROP", "IMG"]
        for word in keywords:
            if word in text.upper():
                score += 20
        
        # Calculate Confidence Level
        if score > 50: confidence = 95
        elif score > 20: confidence = 60
        else: confidence = 10
        
        return score, confidence

# --- API EMAIL FUNCTION ---
def send_api_email(attack_type, ip, confidence):
    print(f"[API] 🚀 Initiating Alert for {attack_type}...")

    # JSON Payload for Formspree
    payload = {
        "subject": f"🚨 ASTRA ALERT: {attack_type} Detected!",
        "message": f"""
        [ASTRA ACTIVE DEFENSE SYSTEM]
        -----------------------------
        CRITICAL THREAT DETECTED
        
        ATTACK TYPE: {attack_type}
        SOURCE IP:   {ip}
        CONFIDENCE:  {confidence}%
        ACTION:      Blocked by Firewall
        TIME:        {datetime.datetime.now()}
        
        This is an automated alert from your ASTRA Project.
        """
    }
    
    try:
        # Send POST request to API
        response = requests.post(EMAIL_API_URL, json=payload)
        
        if response.status_code == 200:
            print("[API] ✅ EMAIL SENT SUCCESSFULLY VIA API!")
        else:
            print(f"[API] ❌ API Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[API] ❌ Connection Error: {e}")

def is_ip_blocked(ip):
    if ip in BLOCKED_IPS:
        if datetime.datetime.now() < BLOCKED_IPS[ip]:
            return True
        else:
            del BLOCKED_IPS[ip]
    return False

def block_ip(ip, reason):
    # Ban IP for 2 minutes
    BLOCKED_IPS[ip] = datetime.datetime.now() + datetime.timedelta(minutes=2)
    print(f"[NGFW] BLOCKING IP {ip} -> {reason}")

def init_db():
    conn = sqlite3.connect('astra.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, message TEXT)')
    try:
        c.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
        conn.commit()
    except:
        pass
    conn.close()

# MIDDLEWARE: The Firewall Logic
@app.before_request
def firewall_check():
    if is_ip_blocked(request.remote_addr):
        return render_template('firewall_block.html', ip=request.remote_addr, expire=BLOCKED_IPS[request.remote_addr])

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # AI CHECK ON LOGIN (SQL Injection Detection)
        score, conf = AIEngine.analyze_threat(username)
        if score > 50:
             # TRIGGER API EMAIL + FIREWALL
             send_api_email("SQL Injection (Login)", request.remote_addr, conf)
             block_ip(request.remote_addr, f"AI Detected Anomaly (Score: {score})")
             return render_template('firewall_block.html', ip=request.remote_addr, expire=BLOCKED_IPS[request.remote_addr])

        conn = sqlite3.connect('astra.db')
        c = conn.cursor()
        try:
            # VULNERABLE QUERY
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            c.execute(query)
            if c.fetchone():
                session['user'] = username
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid Credentials"
        except:
            error = "Database Error"
    return render_template('login.html', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        alert_text = request.form['alert_text']
        
        # AI CHECK ON DASHBOARD INPUT (Buffer/XSS Detection)
        score, conf = AIEngine.analyze_threat(alert_text)
        if score > 50:
             # TRIGGER API EMAIL + FIREWALL
             send_api_email("Buffer/XSS Attack", request.remote_addr, conf)
             block_ip(request.remote_addr, f"AI Detected High Threat (Conf: {conf}%)")
             return render_template('firewall_block.html', ip=request.remote_addr, expire=BLOCKED_IPS[request.remote_addr])

        # VULNERABLE STORE (XSS)
        conn = sqlite3.connect('astra.db')
        c = conn.cursor()
        c.execute(f"INSERT INTO alerts (message) VALUES ('{alert_text}')")
        conn.commit()
        conn.close()

        # VULNERABLE BINARY CALL (Buffer Overflow)
        if os.path.exists("./vuln_backend"):
            subprocess.run(["./vuln_backend", alert_text], capture_output=True)

    conn = sqlite3.connect('astra.db')
    c = conn.cursor()
    c.execute("SELECT message FROM alerts")
    alerts = c.fetchall()
    conn.close()

    # Data for HEATMAP
    risk_data = [
        {'node': 'Web App', 'cve': 'CVE-2021-XSS', 'risk': 'Critical'},
        {'node': 'Database', 'cve': 'Weak Auth', 'risk': 'High'},
        {'node': 'File Srv', 'cve': 'Anon FTP', 'risk': 'Medium'},
        {'node': 'Client', 'cve': 'None', 'risk': 'Low'}
    ]
    return render_template('dashboard.html', user=session['user'], alerts=alerts, output="", risks=risk_data)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # Runs on all interfaces so Greenbone/ZAP can scan it
    app.run(host='0.0.0.0', port=5000)
