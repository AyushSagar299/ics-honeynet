"""
decoy_hmi.py -- a fake HMI login page (a honeypot).

It looks like the login screen of a plant operator panel. There is no real
account behind it -- it always rejects the login. But it LOGS every attempt
(username, password, source IP), so a credential brute-force attack against it
is fully recorded. That log is evidence for the project.
"""

import os
import json
import datetime

from flask import Flask, request

app = Flask(__name__)
LOG_FILE = os.environ.get("HMI_LOG", "hmi_attempts.log")
PORT = int(os.environ.get("HMI_PORT", "8090"))

PAGE = """<html><body style="font-family:sans-serif">
<h2>WaterWorks SCADA &mdash; Operator Login</h2>
<form method="post" action="/login">
  User: <input name="username"><br><br>
  Pass: <input name="password" type="password"><br><br>
  <input type="submit" value="Login">
</form>
</body></html>"""


@app.route("/")
def index():
    return PAGE


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entry = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "ip": request.remote_addr,
            "username": request.form.get("username", ""),
            "password": request.form.get("password", ""),
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print("login attempt:", entry, flush=True)
        # always fail -- it is a honeypot, there is nothing to log into
        return PAGE + "<p>Invalid credentials</p>", 401
    return PAGE


if __name__ == "__main__":
    print(f"Decoy HMI login honeypot on port {PORT}. Every attempt is logged.", flush=True)
    app.run(host="0.0.0.0", port=PORT)
