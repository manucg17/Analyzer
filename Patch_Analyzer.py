import re
import os
import logging
import smtplib
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
            'naming_conventions_check': 0,
        }
        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        def filter_out_http_requests(record):
            message = record.getMessage()
            if "GET /upload" in message and "HTTP/1.1" in message:
                return False  # Do not log messages containing "GET /upload HTTP/1.1"
            return True  # Log all other messages

        # Add the filter to the logger
        logger = logging.getLogger(__name__)
        logger.addFilter(filter_out_http_requests)        

        # Initialize error count
        self.error_count = 0

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

    def get_log_file_name(self):
        current_datetime = datetime.now().strftime("%H-%M-%S-on-%d-%m-%Y")
        log_folder = self.script_path.parent / "Logs"
        log_folder.mkdir(parents=True, exist_ok=True)  # Create Logs folder if it doesn't exist
        os.chmod(log_folder, 0o777)  # Set permission to 777
        log_file_name = f"Logs-{self.script_path.stem}-at-{current_datetime}.log"
        return log_folder / log_file_name

    def run_analysis(self):
        try:
            # Print start of patch analysis
            print("Starting Patch Analysis.")
            # Creating Log with Analysis in Log Directory
            logging.info("Starting Patch Analysis.")

            self.process_patch_file()

            # Print summary of the analysis results
            print("Patch Analysis completed.")
            # Creating Log with Analysis in Log Directory
            logging.info("Patch Analysis completed.")

            # Add summary table to log
            self.add_summary_to_log()

            # Email the log file
            sender_email = self.sender_email
            sender_password = self.sender_password
            recipient_email = self.recipient_email
            attachment_path = self.log_file
            send_email(sender_email, sender_password, recipient_email, attachment_path, self.counts)

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

    def process_patch_file(self):
        try:
            with open(self.script_path, "r") as patch_file:
                # Read the contents of the patch file
                patch_content = patch_file.readlines()

            # Initialize variables to keep track of the current hunk
            current_hunk = None
            current_hunk_lines = []

            # Process each line in the patch content
            for line in patch_content:
                # Check if the line is the start of a new hunk
                if line.startswith('@@'):
                    # If we have a current hunk, process it
                    if current_hunk is not None:
                        self.process_hunk(current_hunk, current_hunk_lines)
                        current_hunk_lines = []

                    # Parse the new hunk information
                    current_hunk = self.parse_hunk_header(line)
                else:
                    # Add the line to the current hunk's lines
                    current_hunk_lines.append(line.strip())

            # Process the last hunk if it exists
            if current_hunk is not None:
                self.process_hunk(current_hunk, current_hunk_lines)
                
        except FileNotFoundError:
            logging.error(f"Patch file not found: {self.script_path}")
        except IndexError as e:
            logging.error(f"IndexError: {str(e)}")
        except ValueError as e:
            logging.error(f"ValueError: {str(e)}")
        except Exception as e:
            logging.error(f"Error processing patch file: {str(e)}")

    def parse_hunk_header(self, hunk_header):
        # Parse the hunk header to get the start line
        parts = hunk_header.split(' ')
        start_line = int(parts[1].split(',')[0][1:])  # Remove the leading '+' or '-' sign
        return {"start_line": start_line}

    def process_hunk(self, hunk_info, hunk_lines):
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
                logging.debug(f"Added line: {stripped_line}")
                self.check_patch_indentation(stripped_line, hunk_info, last_unchanged_line_indentation, previous_line)
                self.check_excess_whitespace(line, hunk_info, previous_line)
                self.check_patch_naming_conventions(hunk_info, hunk_lines)
                self.check_consistency()
            elif line.startswith('-'):
                # This is a deleted line
                logging.debug(f"Deleted line: {stripped_line}")
            else:
                # This is an unchanged line
                logging.debug(f"Unchanged line: {stripped_line}")
                last_unchanged_line_indentation = len(line) - len(line.lstrip())
            previous_line = line
            
    def is_function_definition(self, line):
        # Check if the line is a function definition
        regex = r'\w+\s+\w+\(.*\)\s*'
        return re.match(regex, line.strip()) is not None or ("(" in line and ")" in line and "{" not in line and line.strip().endswith(";"))

    def check_patch_indentation(self, line, hunk_info, reference_indentation, previous_line):
        # Check the indentation of a single line in a hunk
        line_number = hunk_info['start_line']  # Initialize line_number with start_line
        if "\t" in line:
            logging.info(f"Indentation issue at line {line_number}: TAB space used. Convert TABs to spaces.")
            self.counts['indentation_check'] += 1

        if "{" in line and not line.split("//")[0].strip().endswith(" {"):
            logging.info(f"Brace placement issue at line {line_number}: Opening brace should be on the same line as the control statement and preceded by a space.")
            self.counts['indentation_check'] += 1

        if line.strip().startswith("#include"):
            if not re.match(r'^#include\s+<[^>]+>$', line.strip()):
                logging.info(f"Syntax issue at line {line_number}: Incorrect syntax - Include.")

        if line.strip().startswith("Using"):
            if not re.match(r'^Using\s+\S+::\S+;$', line.strip()):
                logging.info(f"Syntax issue at line {line_number}: Incorrect syntax - Using.")

        if line.strip().startswith("typedef"):
            if not re.match(r'^typedef\s+\S+\s+\S+;$', line.strip()):
                logging.info(f"Syntax issue at line {line_number}: Incorrect syntax - Typedef.")
                        
        control_structures = ["if", "else if", "else", "switch", "for", "while", "do", "case", "default"]
        for control_structure in control_structures:
            if line.lstrip().startswith(control_structure):
                # This is a control statement, check the indentation
                expected_indentation = " " * 4  # As per your company's coding standard
                actual_indentation = len(line) - len(line.lstrip())
                if actual_indentation != expected_indentation:
                    logging.info(f"Indentation issue at line {line_number}: Incorrect indentation for {control_structure} statement.")
                    self.counts['indentation_check'] += 1

        if reference_indentation is not None and len(line) - len(line.lstrip()) != reference_indentation:
            logging.info(f"Indentation issue at line {line_number}: Incorrect indentation.")
            self.counts['indentation_check'] += 1

        # New check: New line before the control statement
        if line.strip().startswith(tuple(control_structures)) and previous_line.strip() != '' and not previous_line.strip().startswith('//'):
            logging.info(f"New line issue at line {line_number}: Control statement should be preceded by a new line or a comment.")
            self.counts['indentation_check'] += 1

        # New check: The else keyword on the same line as the closing brace of the if statement
        if 'else' in line.strip() and '}' not in line.strip():
            logging.info(f"Else keyword issue at line {line_number}: The else keyword should be on the same line as the closing brace of the if statement.")
            self.counts['indentation_check'] += 1

        # New check: A space after the closing brackets of if considering }+ +else if/else+ +{ 
        if '}' in line.strip() and 'else' in line.strip() and not line.strip().endswith(' {'):
            logging.info(f"Brace placement issue at line {line_number}: A space is required after the closing brace of if before else.")
            self.counts['indentation_check'] += 1

        # New check: A space after the closing brackets of else if considering }+ +else if/else+ +{ 
        if '}' in line.strip() and 'else if' in line.strip() and not line.strip().endswith(' {'):
            logging.info(f"Brace placement issue at line {line_number}: A space is required after the closing brace of else if before else.")
            self.counts['indentation_check'] += 1
                
        # New check: Closing brace on the next line for control statements
        if line.strip() == '}' and previous_line.strip() != '' and not previous_line.strip().endswith('{'):
            logging.info(f"Brace placement issue at line {line_number}: Closing brace should be on the next line after the control statement.")
            self.counts['indentation_check'] += 1
                    
        # New check: Check if the indentation of the changed lines is the same as the line above and below unless it is an empty line.
        if previous_line.strip() != '' and len(line) - len(line.lstrip()) != len(previous_line) - len(previous_line.lstrip()):
            logging.info(f"Indentation issue at line {line_number}: The indentation of the changed line is not the same as the line above.")
            self.counts['indentation_check'] += 1

        # New check: Indentation of added lines in a new block
        if line.startswith('+') and previous_line.strip().endswith('{'):
            # This is a new block, so the indentation should be more than the previous line
            expected_indentation = len(previous_line) - len(previous_line.lstrip()) + 4  # Assuming 4 spaces for each indentation level
            actual_indentation = len(line) - len(line.lstrip())
            if actual_indentation != expected_indentation:
                logging.info(f"Indentation issue at line {line_number}: Incorrect indentation for a new block.")
                self.counts['indentation_check'] += 1

        # New check: No leading spaces other than the correct indentation
        if line.startswith(' '):
            expected_indentation = ' ' * (len(line) - len(line.lstrip()))  # Assuming spaces for indentation
            if not line.startswith(expected_indentation):
                logging.info(f"Spacing issue at line {line_number}: Extra leading spaces found.")
                self.counts['indentation_check'] += 1

        # New check: No trailing spaces
        if line.rstrip() != line:
            logging.info(f"Spacing issue at line {line_number}: Trailing spaces found.")
            self.counts['indentation_check'] += 1

        # New check: No more than one space between consecutive words in a line unless it is a commented line or it is in between ""
        if '  ' in line and not line.strip().startswith('//') and not re.search(r'".*  .*"', line):
            logging.info(f"Spacing issue at line {line_number}: Multiple spaces between words found.")
            self.counts['indentation_check'] += 1

        # New check: No multiple new lines
        if line.strip() == '' and previous_line.strip() == '':
            logging.info(f"New line issue at line {line_number}: Multiple consecutive new lines found.")
            self.counts['indentation_check'] += 1
                    
    def check_excess_whitespace(self, line, hunk_info, previous_line):
        # Check for excess white space in a line
        line_number = hunk_info['start_line']  # Initialize line_number with start_line

        # Check for tabs
        if "\t" in line:
            logging.info(f"Indentation issue at line {line_number}: TAB space used. Convert TABs to spaces.")
            self.counts['whitespace_check'] += 1

        # Check for multiple spaces between words
        if '  ' in line and not line.strip().startswith('//') and not re.search(r'".*  .*"', line):
            logging.info(f"Spacing issue at line {line_number}: Multiple spaces between words found.")
            self.counts['whitespace_check'] += 1

        # Check for trailing spaces
        if line.rstrip() != line:
            logging.info(f"Spacing issue at line {line_number}: Trailing spaces found.")
            self.counts['whitespace_check'] += 1

        # Check for multiple consecutive new lines
        if line.strip() == '' and previous_line.strip() == '':
            logging.info(f"New line issue at line {line_number}: Multiple consecutive new lines found.")
            self.counts['whitespace_check'] += 1

        # Check for leading spaces other than the correct indentation
        if line.startswith(' '):
            expected_indentation = ' ' * (len(line) - len(line.lstrip()))  # Assuming spaces for indentation
            if not line.startswith(expected_indentation):
                logging.info(f"Spacing issue at line {line_number}: Extra leading spaces found.")
                self.counts['whitespace_check'] += 1

        return self.counts['whitespace_check']

    def check_patch_naming_conventions(self, hunk_info, hunk_lines):
        # Filter out lines that contain C++ keywords
        filtered_lines = [line for line in hunk_lines if not any(keyword in line for keyword in self.cpp_keywords)]

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
                        logging.info(f"{name} naming convention check is not satisfied for '{variable_name}' at line {line_number}")
                        self.counts['naming_conventions_check'] += 1
                        break  # Break out of the loop after finding a match
    def check_consistency(self):
        try:
            with open(self.script_path, "r") as patch_file:
                # Read the contents of the patch file
                patch_content = patch_file.read()

            # Check for consistent use of tabs or spaces for indentation
            if "\t" in patch_content and "    " in patch_content:
                logging.info("Consistency issue: Inconsistent use of tabs and spaces for indentation.")
                self.counts['consistency_check'] += 1

            # Check for consistent line endings (CRLF or LF)
            if "\r\n" in patch_content and "\n" in patch_content:
                logging.info("Consistency issue: Inconsistent line endings (CRLF and LF).")
                self.counts['consistency_check'] += 1

        except FileNotFoundError:
            logging.error(f"Patch file not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error checking consistency: {str(e)}")
                    
def send_email(sender_email, sender_password, recipient_email, attachment_path, counts):
    # Create a multipart message
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email

    # Get the current date and format it as desired
    current_date = datetime.now().strftime('%d-%m-%Y')
    subject = f"Script Analysis Log - {current_date}"
    message['Subject'] = subject

    # Add body to email
    body = "Please find attached the log file for the script analysis.<br><br>"
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
    body += "<br><br>Please Refer to the Attached Log for the detailed Analysis<br><br>Regards<br>"
    
    message.attach(MIMEText(body, 'html'))

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

    # Create SMTP session for sending the mail
    session = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    session.starttls()  # Enable security
    session.login(sender_email, sender_password)  # Login
    text = message.as_string()
    session.sendmail(sender_email, recipient_email, text)  # Send email
    session.quit()  # Terminate the session

# Main program
if __name__ == "__main__":
    # Analyze the script
    patch_analyzer = PatchAnalyzer(script_path, recipient_email, encrypted_sender_email, encrypted_sender_password, encryption_key)
    patch_analyzer.run_analysis()