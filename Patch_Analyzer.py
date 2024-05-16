import re
import os
import logging
import smtplib
import socket
from pathlib import Path
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pygments.lexers import get_lexer_by_name
from pygments.token import Token
from encryption_utils import decrypt_data

# Set global configuration values
SMTP_SERVER = 'smtp-mail.outlook.com'
SMTP_PORT = 587

class PatchAnalyzer:
    def __init__(self, script_path, recipient_email, encrypted_sender_email, encrypted_sender_password, encryption_key):
        self.script_path = Path(script_path)
        self.recipient_email = recipient_email
        self.sender_email = decrypt_data(encrypted_sender_email, encryption_key).decode()
        self.sender_password = decrypt_data(encrypted_sender_password, encryption_key).decode()
        self.log_file = self.get_log_file_name()
        self.encryption_key = encryption_key
        self.counts = {
            'indentation_check': 0,
            'whitespace_check':0,
            'naming_conventions_check': 0,
            'consistency_check':0
        }
        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')      
        logging.getLogger().addFilter(self.filter_out_http_requests)

        # Initialize error count
        self.error_count = 0
        
        # Initialize set of analyzed hunks
        self.logged_issues = set()
        
        # Initialize set of analyzed hunks
        self.analyzed_hunks = set()

        # Extract C++ keywords
        self.cpp_keywords = self.extract_cpp_keywords()
        
        self.conventions = {
            'symbol': r'^\w+::',
            'variable_declaration': r'^\s*(?:int|short|long|float|double|char|bool|void)\s+([a-z][a-zA-Z0-9]*)\s*',
            'variable_usage': r'^\s*([a-z][a-zA-Z0-9]*)\s*',
            'function_declaration': r'^\s*(?:int|short|long|float|double|char|bool|void)\s+([a-z][a-zA-Z0-9]*)\(.*\)\s*',
            'function_call': r'^\s*([a-z][a-zA-Z0-9]*)\(.*\)\s*',
            'type_class': r'^\s*([A-Z_]*_)?[A-Z][a-zA-Z0-9]*\s*',
            'constant': r'^\s*([A-Z_]+)\s*',
            'global_variable': r'^\s*(g_[a-z][a-zA-Z0-9]*)\s*',
            'member': r'^\s*(m_[a-zA-Z_][a-zA-Z0-9_]*)\s*',
            'pointer': r'^\s*(p[a-z][a-zA-Z0-9]*)\s*(?:\*|\s\*)'
        }

    def extract_cpp_keywords(self):
        # Get the lexer for C++
        lexer = get_lexer_by_name('cpp')

        # Read the file content
        with open(self.script_path, 'r') as file:
            content = file.read()

        # Tokenize the content
        tokens = lexer.get_tokens(content)

        # Extract keywords
        keywords = set()
        for token_type, token_value in tokens:
            if token_type in Token.Keyword:
                keywords.add(token_value)

        return keywords

    def filter_out_http_requests(self, record):
        server_ip = socket.gethostbyname(socket.gethostname())
        message = record.getMessage()
        if "GET /upload" in message and "HTTP/1.1" in message:
            return False  # Do not log messages containing "GET /upload HTTP/1.1"
        if f"{server_ip} - -" in message:  # Replace the hardcoded IP address with the server's IP address
            return False  # Do not log messages containing the server's IP address
        return True  # Log all other messages

    # Add the filter to the logger
    logger = logging.getLogger(__name__)
    logger.addFilter(filter_out_http_requests)

    def get_log_file_name(self):
        current_datetime = datetime.now().strftime("%H-%M-%S-on-%d-%m-%Y")
        log_folder = self.script_path.parent / "Logs"
        log_folder.mkdir(parents=True, exist_ok=True)  # Create Logs folder if it doesn't exist
        os.chmod(log_folder, 0o777)  # Set permission to 777
        log_file_name = f"Logs-{self.script_path.stem}-at-{current_datetime}.log"
        return log_folder / log_file_name

    def run_analysis(self):
        try:
            # Print start of script analysis
            print(f"Starting Script Analysis of {self.script_path.stem}.")
            # Creating Log with Analysis in Log Directory
            logging.info(f"Starting Script Analysis of {self.script_path.stem}.")

            cpp_or_h_found = self.process_patch_file()

            # Print summary of the analysis results
            print(f"Script Analysis of {self.script_path.stem} Completed.")
            # Creating Log with Analysis in Log Directory
            logging.info(f"Script Analysis of {self.script_path.stem} Completed.")
            
            # Add summary table to log
            self.add_summary_to_log()

            # Email the log file
            sender_email = self.sender_email
            sender_password = self.sender_password
            recipient_email = self.recipient_email
            attachment_path = self.log_file
            send_email(sender_email, sender_password, recipient_email, attachment_path, self.counts, self.script_path.stem, cpp_or_h_found)

        except Exception as e:
            logging.error(f"Error during analysis: {str(e)}")
            self.error_count += 1
            logging.error(f"Error count: {self.error_count}")  # Log the error count

    def add_summary_to_log(self):
        summary = "\n\n---------------------------------------------\n"
        # Initialize a variable to check if any issues were found
        issues_found = False

        value = any(val > 0 for val in self.counts.values())
        if value:
            summary += "\n  Summary of Issues observed:\n"
            summary += "--------------------------------\n"
            summary += "\tCheck\t\t\t\t Count\n"
            summary += "--------------------------------\n"                

            for check, count in self.counts.items():
                if count >= 1:
                    summary += f" {check.ljust(25)}{count}\n"
                    issues_found = True

        if not issues_found:
            # If no issues were found, print the required message
            summary += " No Issues observed after Analyzing the Patch\n"

        summary += "---------------------------------------------\n"
        with open(self.log_file, 'a') as log_file:
            log_file.write(summary)

    def parse_hunk_header(self, hunk_header_line):
        """Parse the hunk header to get the start line."""
        # Split the hunk header line by space
        parts = hunk_header_line.split(' ')
        # The start line is the second part after the '@@'
        start_line = int(parts[1].split(',')[0][1:])  # Remove the leading '+' or '-' sign
        return {"start_line": start_line}

    def extract_hunk_files(self, hunk_header_line):
        """Extract file extensions from the hunk header line."""
        # Split the hunk header line by ' a/' and ' b/' to get the file paths
        files = re.split(' a/| b/', hunk_header_line)[1:]
        # Get the file extensions
        return [os.path.splitext(file)[1] for file in files]

    def process_patch_file(self):
        try:
            with open(self.script_path, "r") as patch_file:
                patch_content = patch_file.readlines()

                # Initialize variables to keep track of the current hunk
                current_hunk = None
                current_hunk_lines = []
                process_current_hunk = False  # Variable to decide whether to process the current hunk
                current_file = None  # Variable to store the current file name
                cpp_or_h_found = False  # Flag to check if a .cpp or .h file is found

                # Process each line in the patch content
                for line in patch_content:
                    if line.startswith("diff --git"):
                        # If we have a current hunk, process it
                        if current_hunk is not None and process_current_hunk:
                            self.process_hunk(current_hunk, current_hunk_lines, current_file)
                            current_hunk_lines = []

                        # Check file extensions in the hunk header
                        hunk_files = self.extract_hunk_files(line)
                        process_current_hunk = any(ext in (".cpp", ".h") for ext in hunk_files)

                        # Set the flag to True if a .cpp or .h file is found
                        if process_current_hunk:
                            cpp_or_h_found = True

                        # Extract the file name from the hunk header
                        current_file = hunk_files[1]  # The second file is the new file

                    elif line.startswith('@@'):
                        # Parse the new hunk information
                        current_hunk = self.parse_hunk_header(line)

                    # Add the line to the current hunk's lines regardless of the file type
                    current_hunk_lines.append(line.strip())

                # Process the last hunk if it exists
                if current_hunk is not None and process_current_hunk:
                    self.process_hunk(current_hunk, current_hunk_lines, current_file)

                # Return the flag indicating whether a .cpp or .h file was found
                return cpp_or_h_found

        except FileNotFoundError:
            logging.error(f"Patch file not found: {self.script_path}")
        except IndexError as e:
            logging.error(f"IndexError: {str(e)}")
        except ValueError as e:
            logging.error(f"ValueError: {str(e)}")
        except Exception as e:
            logging.error(f"Error processing patch file: {str(e)}")

    def process_hunk(self, hunk_info, hunk_lines, file_name):
        # Process the hunk to identify if lines are added, deleted, or modified
        comment_depth = 0
        last_unchanged_line_indentation = None
        previous_line = None
        for line in hunk_lines:
            stripped_line = line[1:].strip()  # Remove the '+' or '-' at the start
            if not stripped_line:
                continue
            if stripped_line.startswith("/*"):
                comment_depth += 1
            if comment_depth > 0:
                if "*/" in stripped_line:
                    comment_depth -= 1
                continue
            if stripped_line.startswith("//"):
                continue

            if line.startswith('+'):
                # This is an added line
                logging.debug(f"Added line in {file_name}: {stripped_line}")
                self.check_patch_indentation(stripped_line, hunk_info, last_unchanged_line_indentation, previous_line)
                self.check_excess_whitespace(line, hunk_info, previous_line)
                self.check_patch_naming_conventions(hunk_info, hunk_lines)
                self.check_consistency()
            elif line.startswith('-'):
                # This is a deleted line
                logging.debug(f"Deleted line in {file_name}: {stripped_line}")
            else:
                # This is an unchanged line
                logging.debug(f"Unchanged line in {file_name}: {stripped_line}")
                last_unchanged_line_indentation = len(line) - len(line.lstrip())
            previous_line = line

    def is_function_definition(self, line):
        # Check if the line is a function definition
        regex = r'\w+\s+\w+\(.*\)\s*'
        return re.match(regex, line.strip()) is not None or ("(" in line and ")" in line and "{" not in line and line.strip().endswith(";"))

    def check_patch_indentation(self, line, hunk_info, reference_indentation, previous_line):
        # Check if this hunk has been analyzed before
        hunk_id = hash(tuple(line))
        if hunk_id in self.analyzed_hunks:
            return
        self.analyzed_hunks.add(hunk_id)

        # Initialize line_number with start_line
        line_number = hunk_info['start_line']

        # Check the indentation of a single line in a hunk
        if "\t" in line:
            if not (line_number, 'tab_space_used') in self.logged_issues:
                logging.info(f"Indentation issue: TAB space used. Convert TABs to spaces at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'tab_space_used'))

        if "{" in line and not line.split("//")[0].strip().endswith(" {"):
            if not (line_number, 'opening_brace') in self.logged_issues:
                logging.info(f"Indentation issue: Opening brace should be on the same line as the control statement and preceded by a space at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'opening_brace'))

        control_structures = ["if", "else if", "else", "switch", "for", "while", "do", "case", "default"]
        for control_structure in control_structures:
            if line.lstrip().startswith(control_structure):
                # This is a control statement, check the indentation
                expected_indentation = " " * 4  # As per your company's coding standard
                actual_indentation = len(line) - len(line.lstrip())
                if actual_indentation != expected_indentation:
                    if not (line_number, f'incorrect_indentation_{control_structure}') in self.logged_issues:
                        logging.info(f"Indentation issue: Incorrect indentation for {control_structure} statement at line {line_number}.")
                        self.counts['indentation_check'] += 1
                        self.logged_issues.add((line_number, f'incorrect_indentation_{control_structure}'))

        if reference_indentation is not None and len(line) - len(line.lstrip()) != reference_indentation:
            if not (line_number, 'incorrect_indentation') in self.logged_issues:
                logging.info(f"Indentation issue: Incorrect indentation at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'incorrect_indentation'))

        # New check: New line before the control statement
        if line.strip().startswith(tuple(control_structures)) and previous_line.strip() != '' and not previous_line.strip().startswith('//'):
            if not (line_number, 'new_line_before_control') in self.logged_issues:
                logging.info(f"Indentation issue: Control statement should be preceded by a new line or a comment at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'new_line_before_control'))

        # New check: The else keyword on the same line as the closing brace of the if statement
        if 'else' in line.strip() and '}' not in line.strip():
            if not (line_number, 'else_keyword_same_line') in self.logged_issues:
                logging.info(f"Indentation issue: The else keyword should be on the same line as the closing brace of the if statement at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'else_keyword_same_line'))

        # New check: A space after the closing brackets of if considering }+ +else if/else+ +{ 
        if '}' in line.strip() and 'else' in line.strip() and not line.strip().endswith(' {'):
            if not (line_number, 'space_after_closing_brace_if') in self.logged_issues:
                logging.info(f"Indentation issue: A space is required after the closing brace of if before else at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'space_after_closing_brace_if'))

        # New check: A space after the closing brackets of else if considering }+ +else if/else+ +{ 
        if '}' in line.strip() and 'else if' in line.strip() and not line.strip().endswith(' {'):
            if not (line_number, 'space_after_closing_brace_else_if') in self.logged_issues:
                logging.info(f"Indentation issue: A space is required after the closing brace of else if before else at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'space_after_closing_brace_else_if'))

        # New check: Closing brace on the next line for control statements
        if line.strip() == '}' and previous_line.strip() != '' and not previous_line.strip().endswith('{'):
            if not (line_number, 'closing_brace_next_line') in self.logged_issues:
                logging.info(f"Indentation issue: Closing brace should be on the next line after the control statement at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'closing_brace_next_line'))

        # New check: Check if the indentation of the changed lines is the same as the line above and below unless it is an empty line.
        if previous_line.strip() != '' and len(line) - len(line.lstrip()) != len(previous_line) - len(previous_line.lstrip()):
            if not (line_number, 'indentation_changed_line') in self.logged_issues:
                logging.info(f"Indentation issue: The indentation of the changed line is not the same as the line above at line {line_number}.")
                self.counts['indentation_check'] += 1
                self.logged_issues.add((line_number, 'indentation_changed_line'))

        # New check: Indentation of added lines in a new block
        if line.startswith('+') and previous_line.strip().endswith('{'):
            # This is a new block, so the indentation should be more than the previous line
            expected_indentation = len(previous_line) - len(previous_line.lstrip()) + 4  # Assuming 4 spaces for each indentation level
            actual_indentation = len(line) - len(line.lstrip())
            if actual_indentation != expected_indentation:
                if not (line_number, 'indentation_added_line') in self.logged_issues:
                    logging.info(f"Indentation issue: Incorrect indentation for a new block at line {line_number}.")
                    self.counts['indentation_check'] += 1
                    self.logged_issues.add((line_number, 'indentation_added_line'))

        # New check: Indentation of removed lines in a new block
        if line.startswith('-') and previous_line.strip().endswith('{'):
            # This is a new block, so the indentation should be more than the previous line
            expected_indentation = len(previous_line) - len(previous_line.lstrip()) + 4  # Assuming 4 spaces for each indentation level
            actual_indentation = len(line) - len(line.lstrip())
            if actual_indentation != expected_indentation:
                if not (line_number, 'indentation_removed_line') in self.logged_issues:
                    logging.info(f"Indentation issue: Incorrect indentation for a new block at line {line_number}.")
                    self.counts['indentation_check'] += 1
                    self.logged_issues.add((line_number, 'indentation_removed_line'))

    def check_excess_whitespace(self, line, hunk_info, previous_line):
        # Check if this hunk has been analyzed before
        hunk_id = hash(tuple(line))
        if hunk_id in self.analyzed_hunks:
            return
        self.analyzed_hunks.add(hunk_id)

        # Check for excess white space in a line
        line_number = hunk_info['start_line']  # Initialize line_number with start_line

        # Check for multiple spaces between words
        if '  ' in line and not line.strip().startswith('//') and not re.search(r'".*  .*"', line):
            if not (line_number, 'multiple_spaces') in self.logged_issues:
                logging.info(f"Whitespace issue : Multiple spaces between words found at line {line_number}.")
                self.counts['whitespace_check'] += 1
                self.logged_issues.add((line_number, 'multiple_spaces'))

        # Check for trailing spaces
        if line.rstrip() != line:
            if not (line_number, 'trailing_spaces') in self.logged_issues:
                logging.info(f"Whitespace issue : Trailing spaces found at line {line_number}.")
                self.counts['whitespace_check'] += 1
                self.logged_issues.add((line_number, 'trailing_spaces'))

        # Check for multiple consecutive new lines
        if line.strip() == '' and previous_line.strip() == '':
            if not (line_number, 'consecutive_new_lines') in self.logged_issues:
                logging.info(f"Whitespace issue : Multiple consecutive new lines found at line {line_number}.")
                self.counts['whitespace_check'] += 1
                self.logged_issues.add((line_number, 'consecutive_new_lines'))

        # Check for leading spaces other than the correct indentation
        if line.startswith(' '):
            expected_indentation = ' ' * (len(line) - len(line.lstrip()))  # Assuming spaces for indentation
            if not line.startswith(expected_indentation):
                if not (line_number, 'extra_leading_spaces') in self.logged_issues:
                    logging.info(f"Whitespace issue : Extra leading spaces found at line {line_number}.")
                    self.counts['whitespace_check'] += 1
                    self.logged_issues.add((line_number, 'extra_leading_spaces'))

    def check_patch_naming_conventions(self, hunk_info, hunk_lines):
        # Check if this hunk has been analyzed before
        hunk_id = hash(tuple(hunk_lines))
        if hunk_id in self.analyzed_hunks:
            return
        self.analyzed_hunks.add(hunk_id)

        # Filter out lines that contain C++ keywords
        filtered_lines = [line for line in hunk_lines if not any(keyword in line for keyword in self.cpp_keywords)]

        # Create a dictionary to store the line numbers and failed checks
        failed_checks = {}

        # Check each line in the filtered hunk
        for line_number, line in enumerate(filtered_lines, start=hunk_info['start_line']):
            # Check if the line is an added line
            if line.startswith('+'):
                # Remove the '+' at the start
                stripped_line = line[1:].strip()

                # Check each naming convention
                for name, pattern in self.conventions.items():
                    match = re.match(pattern, stripped_line)
                    if match:
                        variable_name = match.group(1)
                        # Add the failed check to the dictionary
                        if line_number not in failed_checks:
                            failed_checks[line_number] = {'variable_name': variable_name, 'failed_checks': []}
                        failed_checks[line_number]['failed_checks'].append(name)

        # Log the failed checks
        for line_number, info in failed_checks.items():
            logging.info(f"Naming convention: {', '.join(info['failed_checks'])} check(s) not satisfied for '{info['variable_name']}' at line {line_number}")
            self.counts['naming_conventions_check'] += len(info['failed_checks'])

    def check_consistency(self):
        try:
            with open(self.script_path, "r") as patch_file:
                # Read the contents of the patch file
                patch_content = patch_file.readlines()

            # Check if this hunk has been analyzed before
            hunk_id = hash(tuple(patch_content))
            if hunk_id in self.analyzed_hunks:
                return
            self.analyzed_hunks.add(hunk_id)

            # Check for consistent use of tabs or spaces for indentation
            inconsistent_indentation_lines = [i for i, line in enumerate(patch_content, start=1) if "\t" in line and "    " in line]
            if inconsistent_indentation_lines:
                logging.info(f"Consistency issue: Inconsistent use of tabs and spaces for indentation at lines {inconsistent_indentation_lines}.")
                self.counts['consistency_check'] += 1

            # Check for consistent line endings (CRLF or LF)
            inconsistent_line_endings_lines = [i for i, line in enumerate(patch_content, start=1) if "\r\n" in line and "\n" in line]
            if inconsistent_line_endings_lines:
                logging.info(f"Consistency issue: Inconsistent line endings (CRLF and LF) at lines {inconsistent_line_endings_lines}.")
                self.counts['consistency_check'] += 1

        except FileNotFoundError:
            logging.error(f"Patch file not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error occurred while checking consistency: {str(e)}")

def send_email(sender_email, sender_password, recipient_email, attachment_path, counts, script_name, cpp_or_h_found):
    # Create a multipart message
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email
    recipient_user = recipient_email.split('@')[0]
    recipient_user = recipient_user.capitalize()

    # Get the current date and format it as desired
    current_date = datetime.now().strftime('%d-%m-%Y')

    # Add body to email
    if cpp_or_h_found:    
        subject = f"Script Analysis Log - {script_name} - {current_date}"
        message['Subject'] = subject
        
        body = body = f"Hello {recipient_user},<br><br>"
        body += "Please find attached the log file for the script analysis.<br><br>"
        body += "<u><b><font size='4.5' color='#000000'>Summary:</font></b></u><br><br>"

        # Create a table for counts with added CSS for better styling
        table = "<table style='border-collapse: collapse; border: 4px solid black; width: 50%; background-color: #F0F0F0; margin-left: auto; margin-right: auto;'>"
        table += "<tr><th style='border: 2px solid black; padding: 15px; text-align: left; background-color: #ADD8E6; color: black;'><b>Code Quality Metric</b></th><th style='border: 2px solid black; padding: 15px; text-align: center; background-color: #ADD8E6; color: black; padding-left: 10px; padding-right: 10px;'><b>Anomaly Frequency</b></th></tr>"
        
        # Define a dictionary to map the check names to more understandable terms
        check_names = {
            'indentation_check': 'Indentation Consistency Inspection',
            'whitespace_check': 'Whitespace Reduction Analysis',
            'naming_conventions_check': 'Naming Standards Assessment',
            'consistency_check': 'Code Uniformity Check',
        }

        for check, count in counts.items():
            # Replace the check name with the corresponding term in the email body
            check_name = check_names.get(check, check)
            table += f"<tr><td style='border: 2px solid black; padding: 15px; text-align: left;'>{check_name}</td><td style='border: 2px solid black; padding: 15px; text-align: center;'>{count}</td></tr>"  # Reduce the cell size of the counts column, change the border color to black, increase the padding to 15px, and left-align the text in the first column
        table += "</table>"

        # Adding Table to the Message body
        body += table

        # Add a couple of line breaks and the desired text
        body += "<br><br>Please Refer to the Attached Log for the detailed Analysis<br><br>Regards<br>ScriptAnalyzer-QA<br>"
        # Open the file to be sent  
        filename = os.path.basename(attachment_path)
        attachment = open(attachment_path, "rb")

        # Instance of MIMEBase and named as p
        p = MIMEBase('application', 'octet-stream')

        # To change the payload into encoded form
        p.set_payload((attachment).read())

        # encode into base64
        encoders.encode_base64(p)

        p.add_header('Content-Disposition', "attachment; filename= %s" % filename)  # Use filename instead of attachment_path

        # attach the instance 'p' to instance 'msg'
        message.attach(p)
    else:
        subject = f"Script Analysis:: No C++ Files Detected in Input: {script_name} - {current_date}"
        message['Subject'] = subject
        body = f"Hello {recipient_user},<br><br>"
        body += "We noticed that the patch/diff file you provided doesn't contain any .cpp or .h files. Currently, our ScriptAnalyzer is designed to analyze only these types of files.<br><br>"
        body += "We appreciate your understanding. If you have any .cpp or .h files that need analysis, feel free to send them our way.<br><br>Regards<br>ScriptAnalyzer-QA<br>"

    message.attach(MIMEText(body, 'html'))

    # Create SMTP session for sending the mail
    session = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    session.starttls()  # Enable security
    session.login(sender_email, sender_password)  # Login
    text = message.as_string()
    session.sendmail(sender_email, recipient_email, text)  # Send email
    session.quit()  # Terminate the session

if __name__ == "__main__":
    # Analyze the script
    patch_analyzer = PatchAnalyzer(script_path, recipient_email, encrypted_sender_email, encrypted_sender_password, encryption_key)
    logging.getLogger().addFilter(patch_analyzer.filter_out_http_requests)    
    patch_analyzer.run_analysis()