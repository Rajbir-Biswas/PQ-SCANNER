from flask import Flask, request, render_template_string, send_file
import ssl
import socket
import csv
import io
import re
import os
import requests
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from graph_engine import CryptoGraph, CryptoGraphQueries
from graph_engine import CryptoGraph

app = Flask(__name__)
last_results = []
graph = CryptoGraph()
queries = CryptoGraphQueries(graph)

# ---------------- PORT SCAN ----------------
def scan_ports(domain):
    ports = [21, 22, 80, 443]
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((domain, port))
            open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports


# ---------------- HEADERS CHECK ----------------
def check_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=3)

        headers = r.headers
        issues = []

        if "Strict-Transport-Security" not in headers:
            issues.append("Missing HSTS")

        if "Content-Security-Policy" not in headers:
            issues.append("Missing CSP")

        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options")

        if "Server" in headers:
            issues.append("Server exposed")

        return ", ".join(issues) if issues else "OK"

    except:
        return "Header scan failed"


# ---------------- CRYPTO ANALYSIS ----------------
def extract_crypto(pubkey):
    algo = "Unknown"
    key_size = "Unknown"

    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            algo = "RSA"
            key_size = pubkey.key_size

        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            algo = "ECC"
            key_size = pubkey.key_size

        else:
            algo = type(pubkey).__name__

    except:
        pass

    return algo, key_size


# ---------------- SCAN DOMAIN ----------------
def scan_domain(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                tls = ssock.version()
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                pubkey = cert.public_key()

                issuer = cert.issuer.rfc4514_string()
                expiry = cert.not_valid_after.strftime("%Y-%m-%d")


                algo, key_size = extract_crypto(pubkey)

                # normalize crypto names (VERY IMPORTANT)
                algo = algo.upper()
                ports = scan_ports(domain)
                headers = check_headers(domain)

                # ---------------- GRAPH BUILD ----------------
                domain_node = graph.add_node("Domain", domain)
                cert_node = graph.add_node("Certificate", issuer + "_" + expiry)
                algo_node = graph.add_node("Algorithm", algo)
                key_node = graph.add_node("Key", str(key_size))
                issuer_node = graph.add_node("Issuer", issuer)

                graph.add_edge(domain_node, "uses", cert_node)
                graph.add_edge(cert_node, "uses_algo", algo_node)
                graph.add_edge(algo_node, "has_key", key_node)
                graph.add_edge(cert_node, "signed_by", issuer_node)

                return [
                    domain,
                    tls,
                    algo,
                    key_size,
                    ",".join(map(str, ports)),
                    issuer,
                    expiry,
                    headers
                ]

    except:
        return [domain, "ERROR", "-", "-", "-", "-", "-", "-"]


# ---------------- UI ----------------
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Crypto Intelligence Engine</title>
<style>
body { font-family: Arial; background:#0f172a; color:white; text-align:center; }
textarea { width:60%; padding:10px; }
button { padding:10px 20px; background:#22c55e; border:none; color:white; }
table { margin:auto; border-collapse:collapse; margin-top:20px; }
th, td { padding:10px; border:1px solid #333; }
th { background:#1e293b; }
</style>
</head>
<body>

<h1>⚛️ Crypto Intelligence Engine</h1>

<form method="POST">
<textarea name="domains" placeholder="Enter domains"></textarea><br><br>
<button type="submit">Scan</button>
</form>

{% if results %}
<table>
<tr>
<th>Domain</th>
<th>TLS</th>
<th>Algorithm</th>
<th>Key</th>
<th>Ports</th>
<th>Issuer</th>
<th>Expiry</th>
<th>Headers</th>
</tr>

{% for r in results %}
<tr>
<td>{{r[0]}}</td>
<td>{{r[1]}}</td>
<td>{{r[2]}}</td>
<td>{{r[3]}}</td>
<td>{{r[4]}}</td>
<td>{{r[5]}}</td>
<td>{{r[6]}}</td>
<td>{{r[7]}}</td>
</tr>
{% endfor %}
</table>
{% endif %}

</body>
</html>
"""


# ---------------- ROUTES ----------------
@app.route("/", methods=["GET", "POST"])
def home():
    global last_results
    results = []

    if request.method == "POST":
        domains = re.split(r"[,\s]+", request.form["domains"])
        domains = [d for d in domains if d]

        for d in domains:
            results.append(scan_domain(d))

        last_results = results
        graph.print_graph()

    return render_template_string(HTML, results=results)


@app.route("/download")
def download():
    global last_results

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Domain", "TLS", "Algo", "Key", "Ports", "Issuer", "Expiry", "Headers"])
    writer.writerows(last_results)

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="crypto_report.csv"
    )


@app.route("/query/rsa")
def query_rsa():
    try:
        result = queries.domains_using_algo("RSA")
        return {"domains_using_RSA": result}

    except Exception as e:
        return {"error": str(e)}

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

