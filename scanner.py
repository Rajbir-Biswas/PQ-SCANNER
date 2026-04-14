from flask import Flask, request, render_template_string, send_file
import ssl
import socket
import csv
import io
import re
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

app = Flask(__name__)
last_results = []

# -------- NETWORK SCAN --------
def scan_ports(domain):
    ports = [21, 22, 80, 443]
    results = []

    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((domain, port))
            results.append(f"{port}:OPEN")
            sock.close()
        except:
            results.append(f"{port}:CLOSED")

    return ", ".join(results)

# -------- RISK ENGINE --------
def calculate_risk(algorithm, key_size, tls_version):
    score = 0

    if "RSA" in algorithm:
        score += 40
    elif "ECC" in algorithm:
        score += 30

    if isinstance(key_size, int):
        if key_size <= 2048:
            score += 30
        elif key_size <= 3072:
            score += 20

    if tls_version in ["TLSv1.2"]:
        score += 20
    elif tls_version in ["TLSv1.1"]:
        score += 30

    return min(score, 100)

def estimate_break_time(score):
    if score >= 80:
        return "5-10 years"
    elif score >= 60:
        return "10-15 years"
    elif score >= 40:
        return "15-20 years"
    else:
        return "20+ years"

def get_priority(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

# -------- SIMULATION --------
def simulate_attack(algo, risk_score):
    steps = []

    steps.append("1. Capture encrypted traffic")

    if algo in ["RSA", "ECC"]:
        steps.append("2. Store data for future decryption")

    if risk_score >= 60:
        steps.append("3. Quantum breaks encryption")

    if risk_score >= 40:
        steps.append("4. Sensitive data exposed")

    if risk_score >= 80:
        steps.append("5. Full system compromise")

    return " → ".join(steps)

# -------- RECOMMENDATIONS --------
def get_recommendations(algo, key_size, tls_version, risk_score):
    actions = []

    if algo == "RSA":
        actions.append("Replace RSA with quantum-safe algorithm (Kyber)")
    elif algo == "ECC":
        actions.append("Replace ECC with quantum-safe signatures (Dilithium)")

    if isinstance(key_size, int) and key_size <= 2048:
        actions.append("Upgrade key size to at least 3072-bit or PQC")

    if tls_version in ["TLSv1.1", "TLSv1.2"]:
        actions.append("Upgrade to TLS 1.3")

    if risk_score >= 80:
        actions.append("Immediate upgrade required")
    elif risk_score >= 60:
        actions.append("Upgrade within 2-3 years")
    else:
        actions.append("Monitor and prepare")
    return " | ".join(actions)


def compare_domains(results):
    valid = []

    for r in results:
        try:
            score = int(r[4])
            valid.append(r)
        except:
            continue

    if not valid:
        return "No valid data to compare"

    sorted_results = sorted(valid, key=lambda x: x[4], reverse=True)

    most_risky = sorted_results[0]
    safest = sorted_results[-1]

    return f"Most Vulnerable: {most_risky[0]} ({most_risky[4]}/100) | Safest: {safest[0]} ({safest[4]}/100)"



# -------- MAIN SCAN --------
def scan_domain(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                tls = ssock.version()
                cert_der = ssock.getpeercert(binary_form=True)

                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                pubkey = cert.public_key()

                algo = "Unknown"
                key_size = 0

                if isinstance(pubkey, rsa.RSAPublicKey):
                    algo = "RSA"
                    key_size = pubkey.key_size
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    algo = "ECC"
                    key_size = pubkey.key_size

                current_risk = "LOW"
                quantum_risk = "HIGH" if algo in ["RSA", "ECC"] else "LOW"

                issuer = cert.issuer.rfc4514_string()
                expiry = cert.not_valid_after.strftime("%Y-%m-%d")

                risk_score = calculate_risk(algo, key_size, tls)
                break_time = estimate_break_time(risk_score)
                priority = get_priority(risk_score)

                simulation = simulate_attack(algo, risk_score)
                recommendation = get_recommendations(algo, key_size, tls, risk_score)

                ports = scan_ports(domain)

                return [
                    domain, tls, algo, key_size,
                    risk_score, break_time, priority,
                    ports, simulation, recommendation
                ]

    except Exception as e:
        return [domain, "FAILED", "-", "-", 0, "-", "ERROR", str(e), "Simulation unavailable", "-"]

# -------- UI --------
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>PQ Scanner</title>
<style>
body { font-family: Arial; background:#0f172a; color:white; text-align:center; }
textarea { width:60%; padding:10px; }

table {
    width: 95%;
}

td {
    font-size: 14px;
}

button { padding:10px 20px; background:#22c55e; border:none; color:white; }
table { margin:auto; border-collapse:collapse; margin-top:20px; }
th, td { padding:10px; border:1px solid #333; }
th { background:#1e293b; }
.high { color:#ef4444; font-weight:bold; }
.low { color:#32c55e; font-weight:bold; }
</style>
</head>
<body>

<h1>⚛️ Quantum Threat Intelligence Platform</h1>
<p style="color:#94a3b8;">
Analyze, Simulate, and Secure against Post-Quantum Attacks
</p>

<form method="POST">
<textarea name="domains" placeholder="google.com, github.com"></textarea><br><br>
<button type="submit">Scan</button>
</form>

{% if results %}
<table>

<tr>
<th>Domain</th>
<th>TLS</th>
<th>Algo</th>
<th>Key</th>
<th>Risk</th>
<th>Break Time</th>
<th>Priority</th>
<th>Ports</th>
<th>Simulation</th>
<th>Fix</th>
</tr>

{% for r in results %}
<tr>
<td>{{r[0]}}</td>
<td>{{r[1]}}</td>
<td>{{r[2]}}</td>
<td>{{r[3]}}</td>
<td>
<div style="width:100px; background:#1e293b; border-radius:5px;">
  <div style="
    width: {{r[4]}}%;
    background: {% if r[4] >= 80 %}#ef4444{% elif r[4] >= 60 %}#f59e0b{% else %}#22c55e{% endif %};
    height:10px;
    border-radius:5px;">
  </div>
</div>
<br>
{{r[4]}}/100
</td>
<td>{{r[5]}}</td>
<td>
<span style="
color:
{% if r[6] == 'CRITICAL' %}#ef4444
{% elif r[6] == 'HIGH' %}#f97316
{% elif r[6] == 'MEDIUM' %}#eab308
{% else %}#22c55e
{% endif %};
font-weight:bold;">
{{r[6]}}
</span>
</td>
<td>{{r[7]}}</td>
<td style="max-width:250px;">{{r[8]}}</td>
<td style="max-width:250px;">{{r[9]}}</td>
</tr>
{% endfor %}
</table>
{% if comparison %}
<h2 style="margin-top:20px; color:#22c55e;">
📊 {{comparison}}
</h2>
{% endif %}
{% endif %}

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    global last_results
    results = []
    comparison = None

    if request.method == "POST":
        domains = re.split(r"[,\s]+", request.form["domains"])
        domains = [d.strip() for d in domains if d.strip()]

        for d in domains:
            results.append(scan_domain(d))

        last_results = results
        comparison = compare_domains(results)

    return render_template_string(HTML, results=results, comparison=comparison)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
