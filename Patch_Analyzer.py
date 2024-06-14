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
COMPANY_STANDARD_INDENTATION = 4

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
        self.logged_errors = set()
        
        # Initialize set of analyzed hunks
        self.analyzed_hunks = set()

        # Extract C++ keywords
        self.cpp_keywords = self.extract_cpp_keywords()
        
        self.conventions = {
            'constructor': r'^\s*\w+::\w+\s*\([a-zA-Z0-9_]*\)?(\s*:\s*m_[a-zA-Z0-9_]*\([a-zA-Z0-9_]*\))?(\s*,\s*m_[a-zA-Z0-9_]*\([a-zA-Z0-9_]*\)\s*){0,7}',
            'function_declaration': r'^\s*(?:int|short|long|float|double|char|bool|void)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\)\s*',
            'function_call': r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\)\s*',
            'variable_declaration': r'^\s*(?:int|short|long|float|double|char|bool|void)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*',
            'variable_usage': r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*',
            'type_class': r'^\s*([A-Z_]*[A-Z][a-zA-Z0-9_]*)\s*',
            'constant': r'^\s*([A-Z_]+)\s*',
            'global_variable': r'^\s*(g_[a-zA-Z_][a-zA-Z0-9_]*)\s*',
            'member': r'^\s*(m_[a-zA-Z_][a-zA-Z0-9_]*)\s*',
            'pointer': r'^\s*(p[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\*|\s\*)'
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
        """Parse the hunk header to get the start line and the number of lines."""
        parts = hunk_header_line.split(' ')
        old_file_info = parts[1].split(',')
        new_file_info = parts[2].split(',')
        
        # Handling new file addition case
        new_file = old_file_info[0] == '-0' and new_file_info[0] == '+1'
        start_line = 1 if new_file else int(new_file_info[0])
        line_count = int(new_file_info[1]) if len(new_file_info) > 1 else 0
        print(f'"old_file_info": {old_file_info},"new_file_info":{new_file_info},"start_line": {start_line}, "current_line_number": {start_line}, "line_count": {line_count}, "new_file": {new_file}')
        return {"start_line": start_line, "current_line_number": start_line, "line_count": line_count, "new_file": new_file}

    def process_patch_file(self):
        """Processes the patch file and performs analysis based on actual line numbers."""
        try:
            with open(self.script_path, "r") as patch_file:
                patch_content = patch_file.readlines()
                current_hunk = None
                current_hunk_lines = []
                current_file = None
                cpp_or_h_found = False
                logged_files = set()
                actual_line_number = 1  # Initialize actual line number

                for line in patch_content:
                    if line.startswith("diff --git") and any(ext in line for ext in [".cpp", ".h"]):
                        if current_hunk is not None and current_hunk_lines:
                            self.process_hunk(current_hunk, current_hunk_lines, current_file, actual_line_number)
                        current_hunk_lines = []
                        parts = line.split()
                        if len(parts) >= 3:
                            # Ignore 'a/' and 'b/' prefixes
                            old_file = parts[2][2:]
                            new_file = parts[3][2:]
                            old_file_ext = os.path.splitext(old_file)[1]
                            new_file_ext = os.path.splitext(new_file)[1]
                            process_current_hunk = any(ext in (".cpp", ".h") for ext in [old_file_ext, new_file_ext])
                        if process_current_hunk:
                            cpp_or_h_found = True
                            current_file = new_file
                        else:
                            continue
                    elif line.startswith('@@') and current_file and cpp_or_h_found:
                        if current_hunk is not None and current_hunk_lines:
                            self.process_hunk(current_hunk, current_hunk_lines, current_file, actual_line_number)
                        current_hunk_lines = []
                        current_hunk = self.parse_hunk_header(line)
                        actual_line_number = current_hunk['start_line']  # Set the actual line number to start line of hunk
                        if current_file not in logged_files:
                            file_ext = os.path.splitext(current_file)[1]
                            if file_ext in ('.cpp', '.h'):
                                logging.info(f"###### DIFF File Analyzed is: {current_file} ######")
                                logged_files.add(current_file)

                    # Append line with actual line number for processing
                    if current_hunk and process_current_hunk:
                        current_hunk_lines.append(line.strip())
                        actual_line_number += 1  # Update actual line number

                if current_hunk is not None and current_hunk_lines:
                    self.process_hunk(current_hunk, current_hunk_lines, current_file, actual_line_number)
                return cpp_or_h_found
        except FileNotFoundError:
            logging.error(f"Patch file not found: {self.script_path}")
        except IndexError as e:
            logging.error(f"IndexError: {str(e)}")
        except ValueError as e:
            logging.error(f"ValueError: {str(e)}")
        except Exception as e:
            logging.error(f"Error processing patch file: {str(e)}")

    def process_hunk(self, hunk_info, hunk_lines, current_file, actual_line_number):
        actual_line_number = hunk_info['start_line']
        last_unchanged_line_indentation = None
        previous_line = ""
        failed_checks = {}
        hunk_id = hash(tuple(hunk_lines))
        if hunk_id in self.analyzed_hunks:
            return False
        self.analyzed_hunks.add(hunk_id)
        new_file = hunk_info.get('new_file', False)


        # Process each line and check for issues
        for line in hunk_lines:
            if line.startswith('+'):
                stripped_line = line[1:].strip()

                # Combined Approach
                if '/' not in stripped_line and '*' not in stripped_line:
                    self.check_patch_indentation(hunk_info, hunk_lines, last_unchanged_line_indentation, previous_line, new_file)
                    self.check_patch_naming_conventions(hunk_info, hunk_lines, new_file)
                    self.check_excess_whitespace(hunk_lines, hunk_info)
                    self.check_consistency()

                actual_line_number += 1
            previous_line = line

    def check_patch_indentation(self, hunk_info, hunk_lines, reference_indentation, previous_line, new_file):
        filtered_lines = [line for line in hunk_lines if line.strip() and not line.strip().startswith('//')]
        failed_checks = {}
        in_multiline_comment = False
        control_structures = ["if", "else if", "else", "switch", "for", "while", "do"]
        multiple_spaces_pattern = re.compile(r"[^ ] {2,}[^ ]")
        multiple_new_lines_pattern = re.compile(r"\n{2,}")

        def log_issue(line_number, issue_type):
            if line_number not in failed_checks:
                failed_checks[line_number] = []
            failed_checks[line_number].append(issue_type)

        for line_number, line in enumerate(filtered_lines, start=hunk_info['start_line']):
            if line.startswith('+'):
                stripped_line = line[1:].strip()

                # Check if the line starts or ends a multi-line comment
                if "/*" in stripped_line:
                    in_multiline_comment = True
                if "*/" in stripped_line:
                    in_multiline_comment = False
                    continue
                
                # Skip checking if the line is within a comment or starts with //
                if in_multiline_comment or stripped_line.startswith("//"):
                    continue

                # Check for TAB spaces
                if "\t" in line:
                    log_issue(line_number, 'tab_space_used')

                # Check for multiple spaces between non-space characters
                if multiple_spaces_pattern.search(stripped_line):
                    log_issue(line_number, 'multiple_spaces')

                # Check for multiple new lines
                if multiple_new_lines_pattern.search("\n".join(hunk_lines)):
                    log_issue(line_number, 'multiple_new_lines')

                # Check for curly braces and control statements
                if "{" in stripped_line:
                    # Check if it's a control structure with correct spacing
                    control_structure_found = False
                    for control_structure in control_structures:
                        if stripped_line.startswith(control_structure):
                            control_structure_found = True
                            if not stripped_line.endswith(" {"):
                                log_issue(line_number, 'curly_brace_same_line_control_structure')
                            break
                    
                    # If not a control structure, check for function definitions or other uses
                    if not control_structure_found:
                        if stripped_line != "{":
                            # If not a single-line definition, check for closing brace
                            if "}" not in stripped_line:
                                log_issue(line_number, 'curly_brace_next_line_function_definition')
                        else:
                            # Check previous line for control structure
                            if previous_line and any(previous_line.strip().startswith(cs) for cs in control_structures):
                                log_issue(line_number, 'curly_brace_new_line_control_structure')

                # Check for conditions and loops having space after keywords
                for control_structure in control_structures:
                    if stripped_line.startswith(control_structure) and not stripped_line.startswith(control_structure + " "):
                        log_issue(line_number, 'missing_space_after_control_structure')

                # Check for reference indentation
                if reference_indentation is not None and len(line) - len(line.lstrip()) != reference_indentation:
                    log_issue(line_number, 'incorrect_indentation')

                # Check for closing brace on the next line for control statements
                if stripped_line == '}' and previous_line and previous_line.strip() != '' and not previous_line.strip().endswith('{'):
                    log_issue(line_number, 'closing_brace_next_line')

                # Check for indentation of added lines in a new block
                if previous_line and previous_line.strip().endswith('{'):
                    expected_indentation = len(previous_line) - len(previous_line.lstrip()) + COMPANY_STANDARD_INDENTATION
                    actual_indentation = len(line) - len(line.lstrip())
                    if actual_indentation != expected_indentation:
                        log_issue(line_number, 'indentation_added_line')

                # Check for indentation of removed lines in a new block
                if line.startswith('-') and previous_line and previous_line.strip().endswith('{'):
                    expected_indentation = len(previous_line) - len(previous_line.lstrip()) + COMPANY_STANDARD_INDENTATION
                    actual_indentation = len(line) - len(line.lstrip())
                    if actual_indentation != expected_indentation:
                        log_issue(line_number, 'indentation_removed_line')

            previous_line = line

        for line_number, issues in failed_checks.items():
            issue_key = (line_number, tuple(issues))
            if issue_key not in self.logged_errors:
                self.logged_errors.add(issue_key)
                adjusted_line_number = line_number - 1 if new_file else line_number
                logging.info(f"Indentation issues: {', '.join(issues)}: Line {adjusted_line_number}")
                self.counts['indentation_check'] += 1

    def check_patch_naming_conventions(self, hunk_info, hunk_lines, new_file):
        filtered_lines = [line for line in hunk_lines if not any(keyword in line for keyword in self.cpp_keywords)]
        failed_checks = {}
        in_multiline_comment = False

        def log_issue(line_number, variable_name, issue_type):
            if line_number not in failed_checks:
                failed_checks[line_number] = {'variable_name': variable_name, 'failed_checks': []}
            failed_checks[line_number]['failed_checks'].append(issue_type)

        for line_number, line in enumerate(filtered_lines, start=hunk_info['start_line']):
            if line.startswith('+'):
                stripped_line = line[1:].strip()
                
                # Check if the line starts or ends a multi-line comment
                if "/*" in stripped_line:
                    in_multiline_comment = True
                if "*/" in stripped_line:
                    in_multiline_comment = False
                    continue
                
                # Skip checking if the line is within a comment or starts with //
                if in_multiline_comment or stripped_line.startswith("//"):
                    continue
                
                for name, pattern in self.conventions.items():
                    try:
                        match = re.match(pattern, stripped_line)
                        if match:
                            variable_name = match.group(1)
                            log_issue(line_number, variable_name, name)
                    except IndexError:
                        logging.error(f"IndexError: no such group. Line: {stripped_line}, Pattern: {pattern}")

        for line_number, issue_info in failed_checks.items():
            variable_name = issue_info['variable_name']
            issues = issue_info['failed_checks']
            issue_key = (line_number, tuple(issues))
            if issue_key not in self.logged_errors:
                self.logged_errors.add(issue_key)
                adjusted_line_number = line_number - 1 if new_file else line_number
                logging.info(f"Naming convention: {', '.join(issues)} check(s) not satisfied for '{variable_name}': Line {adjusted_line_number}")
                self.counts['naming_conventions_check'] += 1

    def check_excess_whitespace(self, hunk_lines, hunk_info):
        """Analyzes a hunk (patch file section) for excessive whitespace and trailing spaces, keeping track of check counts and logging details of identified issues."""
        # Initialize a counter for combined whitespace checks
        self.counts['whitespace_check'] = 0
        in_multiline_comment = False

        # Compile regex patterns for efficiency
        excessive_whitespace_pattern = re.compile(r"\s{3,}")
        trailing_space_pattern = re.compile(r"\s$")

        # Set to store lines with flagged issues
        lines_with_issues = set()

        # Check each line in the hunk
        for actual_line_number, line in enumerate(hunk_lines, start=hunk_info['start_line']):
            if line.startswith('+'):
                stripped_line = line[1:].strip()  # Remove "+" and trailing spaces
                # Check if the line starts or ends a multi-line comment
                if "/*" in stripped_line:
                    in_multiline_comment = True
                if "*/" in stripped_line:
                    in_multiline_comment = False
                    continue
                
                # Skip checking if the line is within a comment or starts with //
                if in_multiline_comment or stripped_line.startswith("//"):
                    continue
                
                # Check for excessive whitespace
                if excessive_whitespace_pattern.search(stripped_line):
                    match = excessive_whitespace_pattern.search(stripped_line)
                    start_index = match.start()
                    end_index = match.end()
                    # Generate issue line description
                    issue_line = f"Excessive whitespace between characters {start_index} and {end_index}: Line {actual_line_number-1}"
                    # Check if the issue has already been flagged for this line
                    if issue_line not in lines_with_issues:
                        lines_with_issues.add(issue_line)
                        self.counts['whitespace_check'] += 1
                        logging.info(issue_line)

                # Check for trailing spaces
                if trailing_space_pattern.search(line[1:]):  # Check the original line for trailing spaces
                    last_word = stripped_line.split()[-1] if stripped_line else ""
                    issue_line = f"Trailing spaces after '{last_word}': Line {actual_line_number-1}"
                    if issue_line not in lines_with_issues:
                        lines_with_issues.add(issue_line)
                        self.counts['whitespace_check'] += 1
                        logging.info(issue_line)
        
    def check_consistency(self):
        try:
            with open(self.script_path, "r") as patch_file:
                # Read the contents of the patch file
                patch_content = patch_file.readlines()

            # Check for consistent line endings (CRLF or LF)
            inconsistent_line_endings_lines = [i for i, line in enumerate(patch_content, start=1) if "\r\n" in line and "\n" in line]
            inconsistent_line_endings_lines = set(inconsistent_line_endings_lines)  # Convert to set for efficient lookup
            if inconsistent_line_endings_lines:
                logging.info(f"Consistency issue: Inconsistent line endings (CRLF and LF).")
                for line_number in inconsistent_line_endings_lines:
                    logging.info(f"Line {line_number}: {patch_content[line_number-1].strip()}")

        except FileNotFoundError:
            logging.error(f"Patch file not found: {self.script_path}")
            return False
        except Exception as e:
            logging.error(f"Error occurred while checking consistency: {str(e)}")
            return False

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
        body += "Please find attached the log file for the script analysis.<br>"
        body += "<b><font size='4.5' color='#000000'>File Type: </font></b>Unified Diff Patch File<br><br>"
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
        body += "<b><font size='4.5' color='#000000'>File Type: </font></b>Unified Diff Patch File<br><br>"
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