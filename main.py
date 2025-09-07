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
import threading

# --- Constants ---
CONFIG_FILE = "config.json"
USER_LOGS_DIR = "user_logs"
SENDER_ID = "ozoneDEMO"
OTP_EXPIRATION_SECONDS = 300
SESSION_EXPIRATION_DAYS = 30

# --- Initialize App and Load Config ---
app = Flask(__name__)

# --- MODIFIED: Function to reload configuration from file ---
def load_config():
    """Reads the config file and returns it as a dictionary."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"FATAL ERROR: Could not read or parse {CONFIG_FILE}.")
        exit()

# Load initial configuration
credentials = load_config()

def get_credential(key, critical=True):
    """Safely gets a credential from the loaded config."""
    value = credentials.get(key)
    if not value and critical:
        print(f"FATAL ERROR: '{key}' not found in {CONFIG_FILE}. Please add it.")
        exit()
    return value

if not os.path.exists(USER_LOGS_DIR):
    os.makedirs(USER_LOGS_DIR)
    print(f"Created directory: {USER_LOGS_DIR}")

# Load credentials into global variables
CLIENT_ID = get_credential("client_id")
API_KEY = get_credential("api_key")
GROQ_API_KEY = get_credential("groq_api_key")
SMTP_EMAIL = get_credential("smtp_email")
SMTP_APP_PASSWORD = get_credential("smtp_app_password")
ADMIN_PASSWORD = get_credential("admin_password") # <-- NEW: Load the admin password

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

# --- Helper Functions (Mostly Unchanged) ---
def log_activity(user_email, phone, msg, response_text):
    log_file_path = os.path.join(USER_LOGS_DIR, f"{user_email}.log")
    with open(log_file_path, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] To: {phone} | Message: {msg[:50].replace(chr(10), ' ')}... | Response: {response_text}\n")

def send_email_otp(recipient_email, otp_code):
    # This function now uses the globally loaded SMTP credentials
    email_subject = "Your One-Time Password (OTP) for IZ SMS"
    email_body = f"Hello User,\n\nYour one-time password is to verify IZ SMS is: {otp_code}\n\nThis code is valid for 5 minutes.Please Don't share this code with anyone."
    em = EmailMessage()
    em['From'] = f"IZ SMS <{SMTP_EMAIL}>"
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
    # This function now uses the globally loaded Ozone credentials
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

# --- NEW: CONFIGURATION EDITING ENDPOINT ---
@app.route('/change', methods=['GET', 'POST'])
def change_config():
    """
    Provides a simple web form to edit the configuration file.
    Protected by a simple admin password.
    """
    global credentials, CLIENT_ID, API_KEY, GROQ_API_KEY, SMTP_EMAIL, SMTP_APP_PASSWORD, ADMIN_PASSWORD, groq_client

    if request.method == 'POST':
        # --- Security Check ---
        submitted_password = request.form.get('admin_password')
        if not submitted_password or submitted_password != ADMIN_PASSWORD:
            return "<h1>403 Forbidden</h1><p>Invalid admin password.</p>", 403

        # --- Update Logic ---
        try:
            # Read the latest config to preserve structure and comments
            with open(CONFIG_FILE, 'r') as f:
                current_config = json.load(f)

            # Update values from form, only if they are not empty
            for key in current_config.keys():
                new_value = request.form.get(key)
                if new_value: # Only update if a new value was provided
                    current_config[key] = new_value

            # Write the updated config back to the file
            with open(CONFIG_FILE, 'w') as f:
                json.dump(current_config, f, indent=4)

            # --- IMPORTANT ---
            # Reload the credentials into the running application's global variables
            credentials = current_config
            CLIENT_ID = get_credential("client_id", False)
            API_KEY = get_credential("api_key", False)
            GROQ_API_KEY = get_credential("groq_api_key", False)
            SMTP_EMAIL = get_credential("smtp_email", False)
            SMTP_APP_PASSWORD = get_credential("smtp_app_password", False)
            ADMIN_PASSWORD = get_credential("admin_password", False)
            # Re-initialize Groq client if the key changed
            try:
                groq_client = Groq(api_key=GROQ_API_KEY)
                print("Groq client re-initialized.")
            except Exception as e:
                groq_client = None
                print(f"Warning: Could not re-initialize Groq client. Error: {e}")


            # Return a success message
            return """
            <h1>Configuration Updated!</h1>
            <p>The configuration file has been successfully updated.</p>
            <p><strong>IMPORTANT:</strong> For all changes to take full effect, you may need to <strong>manually restart the server application</strong>.</p>
            <a href="/change">Back to Config Page</a>
            """

        except Exception as e:
            return f"<h1>Error</h1><p>An error occurred while updating the configuration: {e}</p>", 500

    # --- GET Request: Display the form ---
    # We will mask sensitive values for security
    masked_groq = GROQ_API_KEY[:4] + '...' * (1 if GROQ_API_KEY else 0)
    masked_smtp_pass = '******' * (1 if SMTP_APP_PASSWORD else 0)
    masked_api_key = API_KEY[:4] + '...' * (1 if API_KEY else 0)

    # HTML Form as a string
    html_form = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Server Configuration</title>
        <style>
            body {{ font-family: sans-serif; margin: 2em; background-color: #f4f4f9; }}
            .container {{ max-width: 600px; margin: auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2 {{ color: #333; }}
            label {{ display: block; margin-top: 1em; margin-bottom: 0.5em; font-weight: bold; }}
            input[type="text"], input[type="password"] {{ width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }}
            .warning, .info {{ padding: 1em; border-radius: 4px; margin-top: 1em; }}
            .warning {{ background-color: #ffebee; color: #c62828; border: 1px solid #c62828; }}
            .info {{ background-color: #e3f2fd; color: #1565c0; border: 1px solid #1565c0; }}
            button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; margin-top: 1.5em; }}
            button:hover {{ background-color: #45a049; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Server Configuration</h1>
            <p>Change the settings for the application. Leave a field blank to keep its current value.</p>
            
            <div class="info">Current values are shown as placeholders. Sensitive keys are masked.</div>

            <form action="/change" method="post">
                <h2>Ozone SMS API</h2>
                <label for="client_id">Client ID</label>
                <input type="text" id="client_id" name="client_id" placeholder="{CLIENT_ID}">
                
                <label for="api_key">API Key</label>
                <input type="text" id="api_key" name="api_key" placeholder="{masked_api_key}">

                <h2>Groq AI API</h2>
                <label for="groq_api_key">Groq API Key</label>
                <input type="text" id="groq_api_key" name="groq_api_key" placeholder="{masked_groq}">
                
                <h2>SMTP Email (for OTP)</h2>
                <label for="smtp_email">SMTP Email</label>
                <input type="text" id="smtp_email" name="smtp_email" placeholder="{SMTP_EMAIL}">
                
                <label for="smtp_app_password">SMTP App Password</label>
                <input type="text" id="smtp_app_password" name="smtp_app_password" placeholder="{masked_smtp_pass}">

                <hr style="margin-top: 2em;">

                <h2>Authentication</h2>
                <div class="warning">
                    <strong>Security Check:</strong> You must provide the Admin Password to make any changes.
                </div>
                <label for="admin_password">Admin Password</label>
                <input type="password" id="admin_password" name="admin_password" required>

                <button type="submit">Update Configuration</button>
            </form>
        </div>
    </body>
    </html>
    """
    return html_form
# --- END OF NEW ENDPOINT ---

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({"error": "Email address is required."}), 400

    otp = str(secrets.randbelow(1000000)).zfill(6)
    otp_storage[email] = {"otp": otp, "timestamp": time.time()}

    email_thread = threading.Thread(target=send_email_otp, args=(email, otp))
    email_thread.daemon = True
    email_thread.start()

    return jsonify({"message": f"Request received. An OTP will be sent to {email} shortly. It will expire in 5 minutes."})

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
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
        return jsonify({"message": "Login successful.", "session_token": session_token, "email": email})
    else:
        return jsonify({"error": "Invalid OTP."}), 400

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
            model="meta-llama/llama-4-scout-17b-16e-instruct", temperature=0.3, max_tokens=250
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
    print(f"Admin Password configured: {'Yes' if ADMIN_PASSWORD else 'No'}")
    print("Starting server on http://0.0.0.0:8000")
    print("-> To edit configuration, visit http://<your_server_ip>:8000/change")
    app.run(host='0.0.0.0', port=8000, debug=False)

