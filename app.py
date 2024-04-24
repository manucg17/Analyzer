import os
import shutil
import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from Script_Analyzer import ScriptAnalyzer

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Uploads')
ALLOWED_EXTENSIONS = {'cpp', 'h', 'patch', 'diff'}

# Set global configuration values
sender_email = 'scriptanalyzer_qa@thinkpalm.com'
sender_password = 'Scriptanalyzer@321'
SMTP_SERVER = 'smtp-mail.outlook.com'
SMTP_PORT = 587

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
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Save the uploaded file to the uploads folder
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Check file type after upload
        if filename.endswith('.cpp') or filename.endswith('.h'):
            # Analyze the C++ script
            analyzer = ScriptAnalyzer(file_path, recipient_email, sender_email, sender_password)
            try:
                analyzer.run_analysis()
                flash('C++ script successfully uploaded and analyzed. Email sent successfully')
            except Exception as e:
                flash(f'Error analyzing the C++ script and sending email: {str(e)}', 'error')
        elif filename.endswith('.diff') or filename.endswith('.patch'):
            # Analyze the unified diff file
            analyzer = PatchAnalyzer(file_path, recipient_email, sender_email, sender_password)
            try:
                analyzer.analyze_diff_content()
                flash('Unified diff file successfully uploaded and analyzed. Email sent successfully')
            except Exception as e:
                flash(f'Error analyzing the unified diff file and sending email: {str(e)}', 'error')
        else:
            flash('Allowed file types are .cpp, .h, .diff, .patch', 'error')
            
        return redirect(url_for('index'))
    else:
        flash('Allowed file types are .cpp, .h, .diff, .patch', 'error')
        return redirect(request.url)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)