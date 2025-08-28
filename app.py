from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, make_response, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from vercel_kv import kv
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime, timedelta
import random
import csv
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import re
from io import BytesIO
from google.cloud import vision
from google.oauth2 import service_account
import resend

# --- APP & EXTENSIONS SETUP ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_development')

# Configure Resend for Emails
resend.api_key = os.environ.get("RESEND_API_KEY")

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to /login if user is not authenticated

# --- USER MODEL & LOADER ---
class User(UserMixin):
    def __init__(self, email, first_name, last_name, password_hash, address, city, province, postal_code, country, license_plate):
        self.id = email # Use email as the unique ID
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password_hash = password_hash
        self.address = address
        self.city = city
        self.province = province
        self.postal_code = postal_code
        self.country = country
        self.license_plate = license_plate

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get(user_id):
        user_data = kv.get(f"user:{user_id}")
        if user_data:
            return User(
                email=user_data['email'], first_name=user_data['first_name'], last_name=user_data['last_name'],
                password_hash=user_data['password_hash'], address=user_data.get('address', ''),
                city=user_data.get('city', ''), province=user_data.get('province', ''),
                postal_code=user_data.get('postal_code', ''), country=user_data.get('country', ''),
                license_plate=user_data.get('license_plate', '')
            )
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- AUTHENTICATION ROUTES (NEW) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.get(request.form['email'])
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email']
        existing_user = User.get(email)
        if existing_user:
            flash('Email address already exists.', 'error')
            return redirect(url_for('signup'))

        new_user = User(
            email=email,
            first_name=request.form['first_name'],
            last_name=request.form['last_name'],
            password_hash=generate_password_hash(request.form['password']),
            address=request.form.get('address', ''), city=request.form.get('city', ''),
            province=request.form.get('province', 'Québec'), postal_code=request.form.get('postal_code', ''),
            country=request.form.get('country', 'Canada'), license_plate=request.form.get('license', '')
        )
        
        # Save user data to Vercel KV
        user_data_to_save = {key: value for key, value in new_user.__dict__.items()}
        kv.set(f"user:{email}", user_data_to_save)

        login_user(new_user, remember=True)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- PROFILE ROUTE (REPLACES setup_profile) ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        user = current_user
        # Update user details
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.license_plate = request.form['license']
        user.address = request.form['address']
        user.city = request.form['city']
        user.province = request.form['province']
        user.postal_code = request.form['postal_code']
        user.country = request.form['country']

        # Save updated data
        user_data_to_save = {key: value for key, value in user.__dict__.items()}
        kv.set(f"user:{user.id}", user_data_to_save)
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

# --- CORE APP ROUTES ---
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/sw.js')
def service_worker():
    response = make_response(send_file('sw.js'))
    response.headers['Content-Type'] = 'application/javascript'
    return response

# --- Initialize Google Cloud Vision client ---
try:
    credentials_json = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS_JSON')
    if credentials_json:
        credentials = service_account.Credentials.from_service_account_info(json.loads(credentials_json))
        client = vision.ImageAnnotatorClient(credentials=credentials)
    else:
        client = None
except Exception:
    client = None

# --- PDF AND PLEA HELPER ROUTES ---
@app.route('/generate_pdf', methods=['POST'])
@login_required
def generate_pdf():
    # ... (Most of the logic from your old generate_pdf is the same) ...
    # ... (We just need to add the user's name and email to the PDF data) ...
    data = request.form
    ticket_number = data.get('ticket_number')
    if not ticket_number or not ticket_number.isdigit() or len(ticket_number) != 9:
        return "Invalid ticket number.", 400

    # Create dynamic data
    transaction = ' 00003' + ''.join([str(random.randint(0, 9)) for _ in range(5)])
    reference_number = ' ' + ''.join([str(random.randint(0, 9)) for _ in range(18)])
    auth_code = ' ' + ''.join([str(random.randint(0, 9)) for _ in range(6)])
    space_raw = data.get('space', '')
    space_cleaned = re.sub(r'[^A-Za-z0-9]', '', space_raw)
    space_caps = ''.join([char.upper() if char.isalpha() else char for char in space_cleaned])
    date_obj = datetime.strptime(data.get('date') + ' ' + data.get('start_time'), '%Y-%m-%d %H:%M')
    adjusted_date_obj = date_obj + timedelta(minutes=3)
    
    values = {
        'Transaction number': transaction,
        'Authorization code': auth_code,
        'Response code': ' 027',
        'Space number': ' ' + space_caps,
        'Start of session': ' ' + adjusted_date_obj.strftime('%Y-%m-%d, %H:%M'),
        'End of session': ' ' + (adjusted_date_obj + timedelta(minutes=10)).strftime('%Y-%m-%d, %H:%M'),
        'Top date line': f" {adjusted_date_obj.strftime('%a, %b %d, %Y at %I:%M %p')}",
        'Reference number': reference_number,
        'Cardholder Name': f" {current_user.first_name} {current_user.last_name}", # NEW
        'Cardholder Email': f" {current_user.email}" # NEW
    }
    
    packet = BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)
    with open('static/Mobicite_Placeholder_Locations.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            field, text = row['field'], values.get(row['field'], row.get('text', ''))
            x_pt, y_pt = float(row['x_in']) * 72, (11 - (float(row['y_in']) + 0.1584)) * 72
            c.setFont("Helvetica", 11)
            c.drawString(x_pt, y_pt, text)

    c.save()
    packet.seek(0)
    
    output = PdfWriter()
    background = PdfReader('static/base_template.pdf')
    overlay = PdfReader(packet)
    page = background.pages[0]
    page.merge_page(overlay.pages[0])
    output.add_page(page)

    final_pdf_in_memory = BytesIO()
    output.write(final_pdf_in_memory)
    final_pdf_in_memory.seek(0)

    # --- SEND EMAIL WITH PDF ATTACHMENT (NEW) ---
    try:
        # Prepare the autofill link
        autofill_url = generate_autofill_url(current_user, data)

        # Send the email
        params = {
            "from": "Tickety <noreply@yourdomain.com>", # IMPORTANT: Set up a domain in Resend
            "to": [current_user.email],
            "subject": f"Your Parking Receipt for Ticket #{ticket_number}",
            "html": f"""
                <p>Hello {current_user.first_name},</p>
                <p>Your parking receipt for ticket number {ticket_number} is attached.</p>
                <p>To automatically fill out the online plea form, click the link below:</p>
                <a href="{autofill_url}" style="padding: 10px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
                    Fill Out My Plea Form
                </a>
                <p>Thank you for using Tickety.</p>
            """,
            "attachments": [
                {
                    "filename": f"Tickety_Receipt_{ticket_number}.pdf",
                    "content": list(final_pdf_in_memory.getvalue()),
                }
            ],
        }
        resend.Emails.send(params)
    except Exception as e:
        print(f"Error sending email: {e}") # Log error but don't stop the user
        flash('PDF generated, but there was an error sending the email.', 'error')

    final_pdf_in_memory.seek(0)
    return send_file(
        final_pdf_in_memory,
        as_attachment=True,
        download_name=f'Tickety_Receipt_{ticket_number}.pdf',
        mimetype='application/pdf'
    )

def generate_autofill_url(user, ticket_data):
    # --- THIS IS WHERE WE BUILD THE AUTOFILL LINK ---
    # We need to inspect the Montreal plea website to get the real field names.
    # For now, these are educated guesses.
    base_url = "https://services.montreal.ca/plaidoyer/rechercher/en" # Update this if needed
    
    plea_text = "I plead not guilty. The parking meter was paid for the entire duration that my vehicle was parked at this location."

    params = {
        "statement": ticket_data.get('ticket_number', ''),
        # --- UPDATE THESE FIELD NAMES ---
        "first_name": user.first_name,
        "last_name": user.last_name,
        "address_line_1": user.address,
        "city": user.city,
        "province": user.province,
        "postal_code": user.postal_code,
        "country": user.country,
        "email": user.email,
        "plea_reason": plea_text
        # --- ADD ANY OTHER FIELDS FOUND ON THE WEBSITE ---
    }
    
    import urllib.parse
    query_string = urllib.parse.urlencode(params)
    return f"{base_url}?{query_string}"


@app.route('/plea-helper')
@login_required
def plea_helper():
    ticket_number = request.args.get('ticket_number', '')
    autofill_url = generate_autofill_url(current_user, {'ticket_number': ticket_number})
    plea_text = "I plead not guilty. The parking meter was paid for the entire duration that my vehicle was parked at this location."
    return render_template('plea_helper.html', user=current_user, autofill_url=autofill_url, plea_text=plea_text, ticket_number=ticket_number)


@app.route('/scan-ticket', methods=['POST'])
@login_required
def scan_ticket():
    # This function's logic remains exactly the same as before.
    if not client:
        return jsonify(success=False, message="OCR client not configured."), 500
    if 'ticket_image' not in request.files:
        return jsonify(success=False, message="No image file provided."), 400
    file = request.files['ticket_image']
    if file.filename == '':
        return jsonify(success=False, message="No file selected."), 400
    try:
        content = file.read()
        image = vision.Image(content=content)
        response = client.document_text_detection(image=image)
        raw_text = response.full_text_annotation.text
        
        ticket_number, space_number, extracted_date, extracted_time = "", "", "", ""

        ticket_match = re.search(r'\b(\d{3})\s*(\d{3})\s*(\d{3})\b', raw_text)
        if ticket_match:
            ticket_number = "".join(ticket_match.groups())
        
        space_match = re.search(r'(PL\d+)', raw_text, re.IGNORECASE)
        if space_match:
            space_number = space_match.group(1).upper()
        
        date_time_match = re.search(r'au\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})', raw_text, re.IGNORECASE) or \
                          re.search(r'Date\s+de\s+signification:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})', raw_text, re.IGNORECASE)
        
        if not date_time_match:
            date_time_match = re.search(r'\b(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})\b', raw_text)

        if date_time_match:
            extracted_date, extracted_time = date_time_match.groups()
        
        return jsonify(
            success=True, ticket_number=ticket_number, space=space_number,
            date=extracted_date, start_time=extracted_time
        )
    except Exception as e:
        return jsonify(success=False, message=f"Error processing image: {str(e)}"), 500

# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
