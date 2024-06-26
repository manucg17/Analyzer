import os
import shutil
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from Script_Analyzer import ScriptAnalyzer
from Patch_Analyzer import PatchAnalyzer
from encryption_utils import encrypt_data, decrypt_data, generate_key, load_key

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Uploads')
ALLOWED_EXTENSIONS = {'cpp', 'h', 'patch', 'diff'}

# Read environment variables for sender's email and password
sender_email = os.getenv('SENDER_EMAIL')
sender_password = os.getenv('SENDER_PASSWORD')

# Load the encryption key if it exists, or generate a new one
encryption_key_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'encryption.key')
encryption_key = load_key() if os.path.exists(encryption_key_path) else generate_key()
# Save the encryption key
with open(encryption_key_path, 'wb') as key_file:
    key_file.write(encryption_key)

# Encrypt the sender_email and sender_password
encrypted_sender_email = encrypt_data(sender_email.encode(), encryption_key)
encrypted_sender_password = encrypt_data(sender_password.encode(), encryption_key)

# Delete the existing directory if it exists
if os.path.exists(UPLOAD_FOLDER):
    shutil.rmtree(UPLOAD_FOLDER)

# Create a new directory
os.makedirs(UPLOAD_FOLDER)

# Set the permission to 777
os.chmod(UPLOAD_FOLDER, 0o777)

@app.route('/')
def index():
    return render_template('index.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    recipient_email = request.form.get('recipient_email')  # Retrieve recipient email from the form
    if 'file' not in request.files:
        return jsonify({'message': 'No file part', 'isError': True}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file', 'isError': True}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Save the uploaded file to the uploads folder
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Check file type after upload
        if filename.endswith('.cpp') or filename.endswith('.h'):
            # Analyze the C++ script
            analyzer = ScriptAnalyzer(file_path, recipient_email, encrypted_sender_email, encrypted_sender_password, encryption_key)
            try:
                analyzer.run_analysis()
                # Remove all handlers from the logger
                for handler in logging.root.handlers[:]:
                    logging.root.removeHandler(handler)
                return jsonify({'message': 'File successfully uploaded and analyzed. Email sent successfully', 'isError': False}), 200
            except Exception as e:
                return jsonify({'message': f'Error analyzing the C++ script and sending email: {str(e)}', 'isError': True}), 500
        elif filename.endswith('.diff') or filename.endswith('.patch'):
            # Analyze the unified diff file
            analyzer = PatchAnalyzer(file_path, recipient_email, encrypted_sender_email, encrypted_sender_password, encryption_key)
            try:
                analyzer.run_analysis()
                # Remove all handlers from the logger
                for handler in logging.root.handlers[:]:
                    logging.root.removeHandler(handler)
                return jsonify({'message': 'Patch/Diff File successfully uploaded and analyzed. Email sent successfully', 'isError': False}), 200
            except Exception as e:
                return jsonify({'message': f'Error analyzing the Patch/Diff file - Email sent : {str(e)}', 'isError': True}), 500

    else:
        return jsonify({'message': 'Allowed file types are .cpp, .h, .diff, .patch', 'isError': True}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)