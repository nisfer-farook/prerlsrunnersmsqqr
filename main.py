from flask import Flask, request, jsonify, g
from groq import Groq
import requests
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
import secrets
import time
from datetime import datetime
from functools import wraps
import threading  # <--- ADD THIS IMPORT

# --- Constants ---
CONFIG_FILE = "config.json"
USER_LOGS_DIR = "user_logs"
SENDER_ID = "ozoneDEMO"
OTP_EXPIRATION_SECONDS = 300
SESSION_EXPIRATION_DAYS = 30

# --- Initialize App and Load Config ---
app = Flask(__name__)

def load_config_or_exit(key):
    if key not in credentials:
        print(f"FATAL ERROR: '{key}' not found in {CONFIG_FILE}. Please add it.")
        exit()
    return credentials[key]

try:
    with open(CONFIG_FILE, "r") as f:
        credentials = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    print(f"FATAL ERROR: Could not read or parse {CONFIG_FILE}.")
    exit()

if not os.path.exists(USER_LOGS_DIR):
    os.makedirs(USER_LOGS_DIR)
    print(f"Created directory: {USER_LOGS_DIR}")

# Load credentials
CLIENT_ID = load_config_or_exit("client_id")
API_KEY = load_config_or_exit("api_key")
GROQ_API_KEY = load_config_or_exit("groq_api_key")
SMTP_EMAIL = load_config_or_exit("smtp_email")
SMTP_APP_PASSWORD = load_config_or_exit("smtp_app_password")

# In-memory storage for OTPs and Session Tokens
otp_storage = {}
session_tokens = {}

# Initialize Groq Client
try:
    groq_client = Groq(api_key=GROQ_API_KEY)
except Exception as e:
    groq_client = None
    print(f"Warning: Could not initialize Groq client. AI features disabled. Error: {e}")

# --- Authentication Decorator (Unchanged) ---
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({"error": "Malformed Authorization header."}), 401
        if not token:
            return jsonify({"error": "Authentication Token is missing!"}), 401
        session_data = session_tokens.get(token)
        if not session_data:
            return jsonify({"error": "Invalid or expired Token. Please log in again."}), 401
        session_age_seconds = time.time() - session_data.get('timestamp', 0)
        if session_age_seconds > (SESSION_EXPIRATION_DAYS * 24 * 60 * 60):
            del session_tokens[token]
            return jsonify({"error": "Session has expired. Please log in again."}), 401
        g.user_email = session_data['email']
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions (Unchanged) ---
def log_activity(user_email, phone, msg, response_text):
    log_file_path = os.path.join(USER_LOGS_DIR, f"{user_email}.log")
    with open(log_file_path, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] To: {phone} | Message: {msg[:50].replace(chr(10), ' ')}... | Response: {response_text}\n")

def send_email_otp(recipient_email, otp_code):
    email_subject = "Your One-Time Password (OTP) for Ozone SMS Sender"
    email_body = f"Hello,\n\nYour one-time password is: {otp_code}\n\nThis code is valid for 5 minutes."
    em = EmailMessage()
    em['From'] = f"Ozone SMS Sender <{SMTP_EMAIL}>"
    em['To'] = recipient_email
    em['Subject'] = email_subject
    em.set_content(email_body)
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            smtp.sendmail(SMTP_EMAIL, recipient_email, em.as_string())
        print(f"Successfully sent OTP email to {recipient_email}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to send email to {recipient_email}. Error: {e}")
        return False

def send_ozone_sms(user_email, phone, msg):
    params = {"user_id": CLIENT_ID, "api_key": API_KEY, "sender_id": SENDER_ID, "message": msg, "recipient_contact_no": phone}
    try:
        response = requests.get("https://api.ozonesender.com/v1/send/", params=params, timeout=10)
        is_http_success = 200 <= response.status_code < 300
        response_text = response.text
        is_payload_success = "success" in response_text.lower() if response_text else False
        is_success = is_http_success or is_payload_success
        log_response = f"Success (HTTP {response.status_code})" if is_http_success and not response_text else response_text
        log_activity(user_email, phone, msg, log_response)
        return {"phone": phone, "success": is_success, "response": log_response}
    except requests.exceptions.RequestException as e:
        error_message = f"Network Error: {e}"
        log_activity(user_email, phone, msg, error_message)
        return {"phone": phone, "success": False, "response": error_message}

# --- API Endpoints ---

# --- MODIFIED /request-otp ENDPOINT ---
@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({"error": "Email address is required."}), 400

    otp = str(secrets.randbelow(1000000)).zfill(6)
    otp_storage[email] = {"otp": otp, "timestamp": time.time()}

    # --- THIS IS THE KEY CHANGE ---
    # Create a new thread to send the email in the background.
    # The main process will not wait for this to finish.
    email_thread = threading.Thread(
        target=send_email_otp,
        args=(email, otp)
    )
    email_thread.daemon = True  # Allows the main app to exit even if this thread is running
    email_thread.start()

    # Immediately send a success response to the client.
    # The client no longer has to wait for the email to be sent.
    return jsonify({
        "message": f"Request received. An OTP will be sent to {email} shortly. It will expire in 5 minutes."
    })
# --- END OF MODIFICATION ---


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    # This function remains unchanged
    data = request.get_json()
    email, otp = data.get('email'), data.get('otp')
    if not email or not otp: return jsonify({"error": "Email and OTP are required."}), 400
    stored_data = otp_storage.get(email)
    if not stored_data or time.time() - stored_data.get('timestamp', 0) > OTP_EXPIRATION_SECONDS:
        if email in otp_storage: del otp_storage[email]
        return jsonify({"error": "Invalid or expired OTP. Please request a new one."}), 400
    if stored_data['otp'] == otp:
        del otp_storage[email]
        session_token = secrets.token_hex(32)
        session_tokens[session_token] = {"email": email, "timestamp": time.time()}
        print(f"New session created for {email}")
        return jsonify({
            "message": "Login successful.",
            "session_token": session_token,
            "email": email
        })
    else:
        return jsonify({"error": "Invalid OTP."}), 400

# --- All other endpoints remain unchanged ---

@app.route('/get-logs', methods=['GET'])
@token_required
def get_logs():
    log_file_path = os.path.join(USER_LOGS_DIR, f"{g.user_email}.log")
    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            logs = f.read()
        return jsonify({"logs": logs})
    except FileNotFoundError:
        return jsonify({"logs": "No log entries found for this user."})
    except Exception as e:
        return jsonify({"error": f"Could not read logs: {e}"}), 500

@app.route('/beautify-message', methods=['POST'])
@token_required
def handle_beautify_request():
    if not groq_client:
        return jsonify({"error": "AI service is not configured on the server."}), 503
    data = request.get_json()
    original_message = data.get('message')
    if not original_message:
        return jsonify({"error": "No message provided."}), 400
    prompt = (
        "You are an expert SMS message editor. Your task is to refine the user's message. "
        "Make it more professional, clear, and grammatically correct. "
        "The most important rule is that the final message MUST be under 200 characters. "
        "If the original message is long, you must condense it while preserving the core meaning and tone. "
        "If it's already short, simply improve its clarity without making it significantly longer. "
        "Your entire response must ONLY be the final, edited message. Do not add any extra commentary, greetings, or explanations."
    )
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[{"role": "system", "content": prompt}, {"role": "user", "content": original_message}],
            model="llama3-70b-8192", temperature=0.3, max_tokens=250
        )
        beautified_text = chat_completion.choices[0].message.content.strip()
        if len(beautified_text) > 200:
             beautified_text = beautified_text[:197] + "..."
        return jsonify({"beautified_text": beautified_text})
    except Exception as e:
        print(f"Error calling Groq API: {e}")
        return jsonify({"error": f"An error occurred with the AI service: {e}"}), 500

@app.route('/send-sms', methods=['POST'])
@token_required
def handle_send_request():
    data = request.get_json()
    result = send_ozone_sms(g.user_email, data['phone'], data['message'])
    return jsonify(result)

@app.route("/GET", methods=["GET"])
def alive():
    return "Bot is alive", 200


# --- Main Entry Point (Unchanged) ---
if __name__ == '__main__':
    print("--- Ozone SMS Backend Server ---")
    print(f"Ozone Client ID loaded: {'Yes' if CLIENT_ID else 'No'}")
    print(f"Groq API Key loaded: {'Yes' if GROQ_API_KEY else 'No'}")
    print(f"SMTP Email configured: {'Yes' if SMTP_EMAIL else 'No'}")
    print("Starting server on http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8000, debug=False)
