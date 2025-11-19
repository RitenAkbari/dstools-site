# app.py
import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

# load .env if present
load_dotenv()

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ds_app")

# ---------- CONFIG (defaults set to values you provided) ----------
# If you prefer to keep these in .env, remove the defaults below and set values in .env
GOOGLE_SA_JSON_PATH = os.getenv("GOOGLE_SA_JSON_PATH", "ds-website-478411-a006dae0df18.json")
SPREADSHEET_ID = os.getenv("SPREADSHEET_ID", "1-FVxNf9xpvN1zssQW_MLY0YSlne8usVLaukrudan3CE")
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "0")) if os.getenv("SMTP_PORT") else None
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "please-change-this-in-prod")

log.info("Configuration: spreadsheet_id set? %s | service-account.json exists? %s",
         bool(SPREADSHEET_ID), os.path.exists(GOOGLE_SA_JSON_PATH))

# sheet columns we will use:
SHEET_COLUMNS = ["timestamp", "event", "name", "email", "password_hash", "notes"]

# ---------- Flask app ----------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# ---------- Google Sheets helpers ----------
def get_sheet():
    """Return first worksheet object. Raises helpful errors when misconfigured."""
    if not SPREADSHEET_ID:
        raise RuntimeError("SPREADSHEET_ID not set. Set it in .env or in app.py configuration.")
    if not os.path.exists(GOOGLE_SA_JSON_PATH):
        raise RuntimeError(f"Service account JSON not found at: {GOOGLE_SA_JSON_PATH}")

    try:
        creds = Credentials.from_service_account_file(
            GOOGLE_SA_JSON_PATH,
            scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"],
        )
        gc = gspread.authorize(creds)
        sh = gc.open_by_key(SPREADSHEET_ID)
        ws = sh.sheet1
        # ensure header exists (if header is missing, insert it)
        try:
            header = ws.row_values(1)
            if not header or len(header) < len(SHEET_COLUMNS):
                log.info("Header row missing or too short — writing header row to sheet.")
                ws.insert_row(SHEET_COLUMNS, index=1)
        except Exception as e:
            log.debug("Could not read/write header row: %s", e)
        return ws
    except Exception as e:
        log.exception("Failed to open spreadsheet. Check: SPREADSHEET_ID correctness, JSON path, and sheet sharing.")
        raise

def append_event(event, name="", email="", password_hash="", notes=""):
    ts = datetime.utcnow().isoformat(sep=" ", timespec="seconds") + " UTC"
    row = [ts, event, name, email, password_hash, notes]
    try:
        ws = get_sheet()
        ws.append_row(row, value_input_option="USER_ENTERED")
        log.info("Appended row to sheet: %s", row[:4])
        return True
    except Exception as e:
        log.exception("Error appending to sheet")
        return False

def find_user_by_email(email):
    """Return a dict-like row for the given email, or None."""
    try:
        ws = get_sheet()
        records = ws.get_all_records()
        # try to find exact email match in records
        for row in records:
            # Try to find email in any value of the row (case-insensitive)
            for k, v in row.items():
                if isinstance(v, str) and v.strip().lower() == email.lower():
                    return row
        # fallback: check raw rows (useful if sheet header isn't standard)
        all_vals = ws.get_all_values()
        for r in all_vals[1:]:
            if len(r) >= 4 and r[3].strip().lower() == email.lower():
                return {
                    "timestamp": r[0] if len(r) > 0 else "",
                    "event": r[1] if len(r) > 1 else "",
                    "name": r[2] if len(r) > 2 else "",
                    "email": r[3] if len(r) > 3 else "",
                    "password_hash": r[4] if len(r) > 4 else "",
                }
        return None
    except Exception as e:
        log.exception("Error reading sheet in find_user_by_email")
        return None

# ---------- optional email notification ----------
def send_notification(subject, body):
    if not OWNER_EMAIL or not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        log.debug("SMTP/owner not configured; skipping notification.")
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = OWNER_EMAIL
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        log.info("Notification email sent.")
        return True
    except Exception as e:
        log.exception("Failed to send notification email.")
        return False

# ---------- Routes ----------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if not email or not password:
            flash("Please enter both email and password.", "error")
            append_event("login_failed", name="", email=email, password_hash="", notes="missing credentials")
            return redirect(url_for("login"))

        user = find_user_by_email(email)
        if not user:
            flash("No account found with that email.", "error")
            append_event("login_failed", name="", email=email, password_hash="", notes="email not found")
            return redirect(url_for("login"))

        # find the password hash field
        pw_hash = ""
        for k, v in user.items():
            if "pass" in k.lower():
                pw_hash = v
                break
        if not pw_hash and "password_hash" in user:
            pw_hash = user["password_hash"]

        if not pw_hash:
            flash("Password not set for this account.", "error")
            append_event("login_failed", name=user.get("name",""), email=email, password_hash="", notes="no pw_hash")
            return redirect(url_for("login"))

        try:
            ok = check_password_hash(pw_hash, password)
        except Exception:
            ok = False

        if ok:
            flash("Login successful.", "success")
            append_event("login_success", name=user.get("name", ""), email=email, password_hash="", notes="")
            send_notification("User logged in", f"User {email} logged in at {datetime.utcnow().isoformat()} UTC")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect password.", "error")
            append_event("login_failed", name=user.get("name", ""), email=email, password_hash="", notes="bad password")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if not name or not email or not password:
            flash("Please fill all fields.", "error")
            return redirect(url_for("signup"))

        existing = find_user_by_email(email)
        if existing:
            flash("An account with this email already exists. Try logging in.", "error")
            return redirect(url_for("signup"))

        pw_hash = generate_password_hash(password)
        ok = append_event("signup", name=name, email=email, password_hash=pw_hash, notes="created via site")
        if not ok:
            flash("Signup failed: could not save to sheet. See server logs.", "error")
            return redirect(url_for("signup"))

        send_notification("New signup", f"New user signed up: {name} <{email}> at {datetime.utcnow().isoformat()} UTC")
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/test_append")
def test_append():
    """Quick test — visit this in a browser to check sheet append."""
    ok = append_event("test_append", name="TEST USER", email="test+append@example.com", password_hash="testhash", notes="test")
    if ok:
        return jsonify({"ok": True, "message": "Appended test row to spreadsheet (check sheet)."})
    else:
        return jsonify({"ok": False, "message": "Append failed. Check server logs."}), 500

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)
