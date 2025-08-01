from flask import Flask, render_template, request, redirect, url_for, send_file, session, jsonify
import os
import json
from datetime import datetime, timedelta
import random
import csv
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import re

# IMPORTANT: These are the new imports for OCR.
try:
    from PIL import Image
    import pytesseract
    # On some systems, you may need to explicitly set the path to your Tesseract executable.
    # For example: pytesseract.pytesseract.tesseract_cmd = r'/usr/local/bin/tesseract'
except ImportError:
    Image = None
    pytesseract = None
    print("Warning: Pillow or pytesseract not found. OCR functionality will be disabled.")


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

PROFILE_PATH = 'profile.json'
TEMPLATE_PDF = 'static/base_template.pdf'
FILLED_PDF = 'static/output.pdf'
CSV_PATH = 'static/Mobicite_Placeholder_Locations.csv'

# Load profiles or create empty
if os.path.exists(PROFILE_PATH):
    with open(PROFILE_PATH, 'r') as f:
        try:
            profiles = json.load(f)
        except json.JSONDecodeError:
            profiles = {}
else:
    profiles = {}

# --- Existing Routes ---
@app.route('/')
def index():
    """Renders the main page, checking for a user profile in the session."""
    profile = session.get('profile')
    return render_template('index.html', profile=profile)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    """Handles user sign-in/profile creation. Stores profile in a file and session."""
    if request.method == 'POST':
        profile = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'address': request.form['address'],
            'email': request.form['email'],
            'license': request.form['license']
        }
        key = profile['email']
        profiles[key] = profile
        with open(PROFILE_PATH, 'w') as f:
            json.dump(profiles, f, indent=2)
        session['profile'] = profile
        return redirect(url_for('index'))
    return render_template('signin.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    """Handles editing an existing user profile."""
    profile = session.get('profile')
    if not profile:
        return redirect(url_for('signin'))
    if request.method == 'POST':
        profile['first_name'] = request.form['first_name']
        profile['last_name'] = request.form['last_name']
        profile['address'] = request.form['address']
        profile['email'] = request.form['email']
        profile['license'] = request.form['license']
        profiles[profile['email']] = profile
        with open(PROFILE_PATH, 'w') as f:
            json.dump(profiles, f, indent=2)
        session['profile'] = profile
        return redirect(url_for('index'))
    return render_template('edit_profile.html', profile=profile)

@app.route('/signout')
def signout():
    """Logs the user out by removing their profile from the session."""
    session.pop('profile', None)
    return redirect(url_for('index'))

@app.route('/generate', methods=['POST'])
def generate():
    """
    Generates a PDF receipt based on form data.
    This route's logic remains unchanged from your original code.
    """
    data = request.form

    ticket_number = data['ticket_number']
    if not ticket_number.isdigit() or len(ticket_number) != 9:
        return "Ticket number must be exactly 9 digits.", 400

    transaction = ' 00003' + ''.join([str(random.randint(0, 9)) for _ in range(5)])
    reference_number = ' ' + ''.join([str(random.randint(0, 9)) for _ in range(18)])
    auth_code = ' ' + ''.join([str(random.randint(0, 9)) for _ in range(6)])
    response_code = ' 027'

    space_raw = data['space']
    space_cleaned = re.sub(r'[^A-Za-z0-9]', '', space_raw)
    space_caps = ''.join([char.upper() if char.isalpha() else char for char in space_cleaned])

    date_obj = datetime.strptime(data['date'] + ' ' + data['start_time'], '%Y-%m-%d %H:%M')
    start_time = date_obj.strftime('%Y-%m-%d, %H:%M')
    end_time = (date_obj + timedelta(minutes=10)).strftime('%Y-%m-%d, %H:%M')
    date_line = f" {date_obj.strftime('%a, %b %d, %Y at %I:%M %p')}"
    transaction_datetime = ' ' + date_obj.strftime('%Y-%m-%d, %H:%M')

    values = {
        'Transaction number': transaction,
        'Authorization code': auth_code,
        'Response code': response_code,
        'Space number': ' ' + space_caps,
        'Start of session': ' ' + start_time,
        'End of session': ' ' + end_time,
        'Top date line': date_line,
        'Reference number': reference_number
    }

    packet_path = 'static/temp.pdf'
    c = canvas.Canvas(packet_path, pagesize=letter)

    with open(CSV_PATH, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            field = row['field']
            text = values.get(field, row['text'])
            x_pt = float(row['x_in']) * 72
            y_pt = (11 - (float(row['y_in']) + 0.1584)) * 72
            c.setFont("Helvetica", 11)
            c.drawString(x_pt, y_pt, text)

    # Add Reference number
    ref_x = 2.0836 * 72
    ref_y = (11 - (6.6827 + 0.1584)) * 72
    c.drawString(ref_x, ref_y, reference_number)

    # Add Transaction Date (new)
    tx_x = 1.9515 * 72
    tx_y = (11 - (4.8789 + 0.1584)) * 72
    c.drawString(tx_x, tx_y, transaction_datetime)

    c.save()

    output = PdfWriter()
    background = PdfReader(TEMPLATE_PDF)
    overlay = PdfReader(packet_path)

    page = background.pages[0]
    page.merge_page(overlay.pages[0])
    output.add_page(page)

    with open(FILLED_PDF, 'wb') as f:
        output.write(f)

    return send_file(FILLED_PDF, as_attachment=True)


# --- NEW: Route for handling the OCR request ---
@app.route('/scan-ticket', methods=['POST'])
def scan_ticket():
    """
    Handles an image upload, performs OCR to extract text, and returns a JSON response.
    """
    # Check if OCR libraries are available
    if not Image or not pytesseract:
        return jsonify(success=False, message="OCR libraries are not installed on the server.")

    # Check if a file was sent in the request
    if 'ticket_image' not in request.files:
        return jsonify(success=False, message="No image file provided.")

    file = request.files['ticket_image']
    if file.filename == '':
        return jsonify(success=False, message="No file selected.")

    if file:
        try:
            # Open the image file from the request stream
            image = Image.open(file.stream)
            
            # Perform OCR on the image to get raw text.
            # Using 'eng+fra' for English and French language support.
            raw_text = pytesseract.image_to_string(image, lang='eng+fra')

            # --- OCR TEXT PARSING LOGIC (Updated based on your ticket image) ---
            ticket_number = ""
            space_number = ""
            extracted_date = ""
            extracted_time = ""

            # 1. Capture the 9-digit ticket number with spaces and remove spaces
            # Pattern: 3 digits, optional space, 3 digits, optional space, 3 digits
            ticket_match = re.search(r'\b(\d{3})\s*(\d{3})\s*(\d{3})\b', raw_text)
            if ticket_match:
                # Combine the captured groups without spaces
                ticket_number = ticket_match.group(1) + ticket_match.group(2) + ticket_match.group(3)

            # 2. Capture the "PL" space number, which is more specific.
            # This avoids picking up "PLATEAU".
            space_match = re.search(r'(PL\d+)', raw_text, re.IGNORECASE)
            if space_match:
                space_number = space_match.group(1).upper() # .upper() for consistency

            # 3. Capture the second date and time (the 'to' date)
            # This is the updated, more robust regex to capture the 'to' date and time.
            date_time_match = re.search(r'to\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})', raw_text, re.IGNORECASE)
            
            # Fallback: if the "to" date is not found, try to find the "Date de signification"
            if not date_time_match:
                date_time_match = re.search(r'Date\s+de\s+signification:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})', raw_text, re.IGNORECASE)
            
            if date_time_match:
                extracted_date = date_time_match.group(1)
                extracted_time = date_time_match.group(2)
            
            # Log the raw text for debugging purposes
            print(f"Raw OCR Text:\n{raw_text}")
            
            # --- END OCR TEXT PARSING LOGIC ---

            return jsonify(
                success=True,
                ticket_number=ticket_number,
                space=space_number,
                date=extracted_date,
                start_time=extracted_time,
                raw_ocr_text=raw_text # Return this for debugging if needed
            )

        except Exception as e:
            # Log any errors that occur during the process
            print(f"OCR Error: {e}")
            return jsonify(success=False, message=f"Error processing image: {str(e)}")

if __name__ == '__main__':
    # Your existing code for running the Flask app
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True) # Enabled debug mode for easier development
