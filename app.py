from flask import Flask, request, render_template_string, send_file
import ssl
import socket
import csv
import io
import os
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

app = Flask(__name__)

last_results = []

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>PQ Scanner Dashboard</title>
</head>
<body>

<h2>Post-Quantum Crypto Scanner</h2>

<form method="POST">
    <textarea name="domains" rows="6" cols="50"
    placeholder="Enter domains (one per line OR space/comma separated)"></textarea><br><br>
    <button type="submit">Scan</button>
</form>

{% if results %}
    <h3>Scan Results ({{ results|length }} domains):</h3>

    <table border="1">
        <tr>
            <th>Domain</th>
            <th>TLS</th>
            <th>Algorithm</th>
            <th>Key Size</th>
            <th>Risk</th>
        </tr>

        {% for r in results %}
        <tr>
            <td>{{ r[0] }}</td>
            <td>{{ r[1] }}</td>
            <td>{{ r[2] }}</td>
            <td>{{ r[3] }}</td>
            <td>{{ r[4] }}</td>
        </tr>
        {% endfor %}
    </table>

    <br>
    <a href="/download">⬇ Download CSV Report</a>
{% endif %}

</body>
</html>
"""

def scan_domain(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=3) as sock:
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

                risk = "HIGH" if algo in ["RSA", "ECC"] else "LOW"

                return [domain, tls, algo, key_size, risk]

    except:
        return [domain, "ERROR", "-", "-", "UNKNOWN"]


@app.route("/", methods=["GET", "POST"])
def home():
    global last_results
    results = []

    if request.method == "POST":
        domains_input = request.form["domains"]

        # ✅ SMART INPUT HANDLING (NO INDENT ERROR)
        domains = re.split(r"[,\s]+", domains_input)
        domains = [d.strip() for d in domains if d.strip()]

        for d in domains:
            results.append(scan_domain(d))

        last_results = results

    return render_template_string(HTML, results=results)


@app.route("/download")
def download():
    global last_results

    if not last_results:
        return "No scan data available. Please run a scan first."

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Domain", "TLS", "Algorithm", "KeySize", "Risk"])
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
