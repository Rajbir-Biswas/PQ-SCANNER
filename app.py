from flask import Flask, request, render_template_string, send_file
import ssl
import socket
import csv
import io
import re
import os
from datetime import datetime
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


# -------- TLS + CERT SCAN --------
def scan_domain(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                tls = ssock.version()
                cert_der = ssock.getpeercert(binary_form=True)

                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                pubkey = cert.public_key()

                algo = "Unknown"
                key_size = "Unknown"

                if isinstance(pubkey, rsa.RSAPublicKey):
                    algo = "RSA"
                    key_size = pubkey.key_size
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    algo = "ECC"
                    key_size = pubkey.key_size

                # Current Risk
                if algo == "RSA" and key_size < 2048:
                    current_risk = "HIGH"
                elif algo == "RSA":
                    current_risk = "LOW"
                elif algo == "ECC":
                    current_risk = "LOW"
                else:
                    current_risk = "UNKNOWN"

                # Quantum Risk
                quantum_risk = "HIGH" if algo in ["RSA", "ECC"] else "LOW"

                issuer = cert.issuer.rfc4514_string()
                expiry = cert.not_valid_after.strftime("%Y-%m-%d")

                # 🔍 NETWORK SCAN
                port_info = scan_ports(domain)

                return [
                    domain,
                    tls,
                    algo,
                    key_size,
                    current_risk,
                    quantum_risk,
                    port_info,
                    issuer,
                    expiry
                ]

    except Exception as e:
        return [domain, "ERROR", "-", "-", "-", "-", "-", str(e), "-"]


# -------- UI --------
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>PQ Scanner Pro</title>
<style>
body { font-family: Arial; background:#0f172a; color:white; text-align:center; }
textarea { width:60%; padding:10px; }
button { padding:10px 20px; background:#22c55e; border:none; color:white; }
table { margin:auto; border-collapse:collapse; margin-top:20px; }
th, td { padding:10px; border:1px solid #333; }
th { background:#1e293b; }
.low { color:#22c55e; font-weight:bold; }
.high { color:#ef4444; font-weight:bold; }
</style>
</head>

<body>

<h1>⚛️ Post-Quantum Scanner PRO</h1>

<form method="POST">
<textarea name="domains" placeholder="Enter domains (google.com, github.com)"></textarea><br><br>
<button type="submit">Scan Now</button>
</form>

{% if results %}
<table>
<tr>
<th>Domain</th>
<th>TLS</th>
<th>Algo</th>
<th>Key</th>
<th>Current</th>
<th>Quantum</th>
<th>Ports</th>
<th>Issuer</th>
<th>Expiry</th>
</tr>

{% for r in results %}
<tr>
<td>{{r[0]}}</td>
<td>{{r[1]}}</td>
<td>{{r[2]}}</td>
<td>{{r[3]}}</td>

<td class="{{ 'low' if r[4]=='LOW' else 'high' }}">{{r[4]}}</td>
<td class="{{ 'high' if r[5]=='HIGH' else 'low' }}">{{r[5]}}</td>

<td>{{r[6]}}</td>
<td>{{r[7]}}</td>
<td>{{r[8]}}</td>
</tr>
{% endfor %}
</table>

<br>
<a href="/download" style="color:#22c55e;">Download Report</a>
{% endif %}

</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def home():
    global last_results
    results = []

    if request.method == "POST":
        domains_input = request.form["domains"]
        domains = re.split(r"[,\s]+", domains_input)
        domains = [d.strip() for d in domains if d.strip()]

        for d in domains:
            results.append(scan_domain(d))

        last_results = results

    return render_template_string(HTML, results=results)


@app.route("/download")
def download():
    global last_results

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Domain", "TLS", "Algo", "Key", "Current Risk", "Quantum Risk", "Ports", "Issuer", "Expiry"])
    writer.writerows(last_results)

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="pq_scan_report.csv"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
