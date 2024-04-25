import re
import os
import logging
import subprocess
import smtplib
from pathlib import Path
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from encryption_utils import decrypt_data

# Set global configuration values
SMTP_SERVER = 'smtp-mail.outlook.com'
SMTP_PORT = 587

# Set global indentation, line count, iteration values and List of all module names
SEQUENCE_LENGTH = 3  # Minimum number of lines in a sequence to consider it for refactoring
REPETITION_THRESHOLD = 3  # Determine the threshold for suggesting refactoring as a function
INDENTATION_SPACES = 4
EXPECTED_LINE_COUNT = 1500
MODULES_ALL = ["sys", "nedbg", "sys_util", "messages", "halApi", "hal_card", 
               "productId", "aos_utils", "SysConfStorage", "HRM_Server", 
               "HRM_State", "HRM_StateElection", "HRM_StateDisabledMaster", 
               "HRM_StateDisabledSlave", "HRM_PeerClient", "HRM_SystemMgrClient", 
               "HRM_StateStandby", "acprof", "platform", "HRM_DataSyncDefs"]

ITERATION_VALUES = {
    'MAX_FUNCTION_COUNT': 3,  # Maximum number of functions expected in the script
    'MAX_SUBROUTINE_COUNT': 3  # Maximum number of subroutines expected in the script
}

class ScriptAnalyzer:
    def __init__(self, script_path, recipient_email, encrypted_sender_email, encrypted_sender_password, encryption_key):
        self.script_path = Path(script_path)
        self.recipient_email = recipient_email
        self.sender_email = decrypt_data(encrypted_sender_email, encryption_key).decode()
        self.sender_password = decrypt_data(encrypted_sender_password, encryption_key).decode()
        self.log_file = self.get_log_file_name()
        self.encryption_key = encryption_key
        self.counts = {
            'total_lines_check': 0,
            'indentation_check': 0,
            'naming_conventions_check': 0,
            'modularization_check': 0,
            'consistency_check': 0,
            'excess_whitespace_check': 0
        }
        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        # Initialize error count
        self.error_count = 0

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
            print("Starting Script Analysis.")
            # Creating Log with Analysis in Log Directory
            logging.info("Starting Script Analysis.")

            # Check for mandatory #include directive
            self.check_include_directive()

            try:
                # Check script indentation
                self.check_total_lines()
            except Exception as e:
                logging.error(f"Error during total lines check: {str(e)}")

            try:
                # Check script indentation
                self.check_indentation()
            except Exception as e:
                logging.error(f"Error during indentation check: {str(e)}")

            try:
                # Check naming conventions
                self.check_naming_conventions()
            except Exception as e:
                logging.error(f"Error during naming conventions check: {str(e)}")

            try:
                # Check modularization
                self.check_modularization()
            except Exception as e:
                logging.error(f"Error during modularization check: {str(e)}")

            # Check file encoding
            self.check_file_encoding()

            try:
                # Check consistency
                self.check_consistency()
            except Exception as e:
                logging.error(f"Error during consistency check: {str(e)}")

            try:
                # Check whitespace usage
                self.check_excess_whitespace()
            except Exception as e:
                logging.error(f"Error during whitespace check: {str(e)}")

            # Print summary of the analysis results
            print("Script Analysis completed.")
            # Creating Log with Analysis in Log Directory
            logging.info("Script Analysis completed.")

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
            summary += " No Issues observed after Analyzing the Script\n"

        summary += "---------------------------------------------\n"
        with open(self.log_file, 'a') as log_file:
            log_file.write(summary)

    def check_include_directive(self):
        try:
            with open(self.script_path, "r") as script_file:
                lines = script_file.readlines()

                first_non_comment_line = None
                in_multiline_comment = False
                for line_number, line in enumerate(lines, start=1):
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    if stripped_line.startswith("/*"):
                        in_multiline_comment = True
                    if in_multiline_comment:
                        if "*/" in stripped_line:
                            in_multiline_comment = False
                        continue
                    if stripped_line.startswith("//"):
                        continue
                    first_non_comment_line = line_number
                    break

                if not first_non_comment_line or not lines[first_non_comment_line - 1].strip().startswith("#include "):
                    logging.error("Mandatory '#include ' directive missing at the beginning of the file.")
                    self.counts['include_directive_check'] = 1  # Increment the count
        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during include directive check: {str(e)}")

    def check_total_lines(self):
        try:
            with open(self.script_path, "r") as script_file:
                lines = script_file.readlines()
                total_lines = len(lines)
                if total_lines > EXPECTED_LINE_COUNT:
                    logging.warning(f'Total number of lines present is:{total_lines}. Expectation: Maximum of {EXPECTED_LINE_COUNT} lines.')
                    self.counts['total_lines_check'] += 1
            logging.info(f"Total lines check completed - Count: {self.counts['total_lines_check']}")
        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during total lines check: {str(e)}")

    def check_indentation(self):
        try:
            with open(self.script_path, "r") as script_file:
                lines = script_file.readlines()

                inside_function = False
                indentation_level = 0
                in_multiline_comment = False

                for line_number, line in enumerate(lines, start=1):
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    if stripped_line.startswith("/*"):
                        in_multiline_comment = True
                    if in_multiline_comment:
                        if "*/" in stripped_line:
                            in_multiline_comment = False
                        continue
                    if stripped_line.startswith("//"):
                        continue

                    if "\t" in line:
                        logging.warning(f"Indentation issue at line {line_number}: TAB space used. Convert TABs to spaces.")
                        self.counts['indentation_check'] += 1

                    if "{" in line and not line.split("//")[0].strip().endswith("{"):
                        logging.warning(f"Brace placement issue at line {line_number}: Opening brace should be on the same line as the control statement.")
                        self.counts['indentation_check'] += 1

                    if line.strip().startswith("#include"):
                        if not re.match(r'^#include\s+\S+', line.strip()):
                            logging.warning(f"Syntax issue at line {line_number}: Incorrect syntax - Include.")
                        continue
                    
                    if line.strip().startswith("Using"):
                        if not re.match(r'^Using\s+\S+', line.strip()):
                            logging.warning(f"Syntax issue at line {line_number}: Incorrect syntax - Using.")
                        continue

                    if line.strip().startswith("typedef"):
                        if not re.match(r'^typedef\s+\S+\s+\S+;', line.strip()):
                            logging.warning(f"Syntax issue at line {line_number}: Incorrect syntax - Typedef.")
                        continue

                    if "{" in line and "(" in line and not inside_function:
                        if line.strip().endswith("{"):
                            inside_function = True
                            continue

                    if inside_function:
                        control_structures = ["if", "else if", "else", "switch", "for", "while", "do", "case", "default"]
                        for control_structure in control_structures:
                            if control_structure in line.strip():
                                if not line.startswith(" " * INDENTATION_SPACES * indentation_level):
                                    logging.warning(f"Indentation issue at line {line_number}: Incorrect indentation for {control_structure} statement.")
                                    self.counts['indentation_check'] += 1
                                if line.strip().endswith("{"):
                                    indentation_level += 1
                            if line.strip().startswith("}"):
                                indentation_level -= 1
                                if indentation_level == 0:
                                    inside_function = False
                                    continue

                    if "do" in line.strip() and "{" in line.strip():
                        indentation_level += 1
                    if "while" in line.strip() and ";" in line.strip() and "do" not in line.strip():
                        indentation_level -= 1

                    if not line.startswith(" " * INDENTATION_SPACES * indentation_level) and line.strip() not in ["{", "}"]:
                        logging.warning(f"Indentation issue at line {line_number}: Incorrect indentation.")
                        self.counts['indentation_check'] += 1

            logging.info(f"Indentation check completed - Count: {self.counts['indentation_check']}")
        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during indentation check: {str(e)}")

    def check_naming_conventions(self):
        reserved_names = ['int', 'short', 'long', 'long long', 'float', 'double', 'long double', 'char', 'wchar_t', 'char16_t', 'char32_t', 'bool', 'void', 'enum', 'struct', 'union']
        try:
            with open(self.script_path, "r") as script_file:
                for line_number, line in enumerate(script_file, start=1):
                    line = line.strip()

                    # Check for symbols prefix corresponding to all module names
                    for module in MODULES_ALL:
                        if line.startswith(module + "::"):
                            logging.warning(f"Symbol with prefix '{module}::': found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1

                    # Check for lower-case variables/functions with reserved data types
                    if re.match(r'^\s*(?:' + '|'.join(reserved_names) + r')\s+[a-z_]\w*\s*;', line.strip()):
                        # Check if the variable or function name is not in lowercase
                        if not re.match(r'^\s*(?:' + '|'.join(reserved_names) + r')\s+[a-z_]\w*\s*;', line.strip()):
                            logging.warning(f"Variable/function not starting with lower-case letter: found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1

                    # Check for upper-case types/classes
                    if re.match(r'\b(class|struct|enum|union|namespace)\s', line):
                        if not re.match(r'\b(?:class|struct|enum|union|namespace)\s+[A-Z]\w*\s*(?:::\w+)*\s*{\s*$', line):
                            logging.warning(f"Class/Types names is not starting with Upper-Case letter: found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1
                    
                    # Check for upper case type/class name or the TYPE keyword convention
                    if (re.search(r'\bTYPE\s', line) and re.search(r';\s*END\s+TYPE\s', line)):
                        if not (re.search(r'\bTYPE\s*\(\s*[a-zA-Z]+\s*\)\s*;', line) and re.search(r';\s*END\s+TYPE\s+[a-zA-Z]+\s*;', line)):
                            logging.warning(f"TYPE keyword not starting with Upper-Case letter: found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1

                    # Check for upper-case constants
                    if re.match(r'^#define\s+[A-Z_]+\s+', line):
                        if not re.match(r'#define [A-Z_]+ .*', line):
                            logging.warning(f"Constant used is not in Upper-Case: found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1

                    # Check for global variables starting with 'g_'
                    if re.match(r'\b(g_[a-zA-Z_]\w*)\b', line):
                        logging.warning(f"Global variable not starting with 'g_': found at line {line_number}")
                        self.counts['naming_conventions_check'] += 1

                    # Check for members starting with 'm_'
                    if re.match(r'(\w+)::\1', line):
                        if not re.match(r'(\w+)::\1\s*\((.*?)\)\s*:\s*\w+\s*\([^)]*\)\s*(?:...).*m_\w+\s*\([^)]*\)*\s*{', line):
                            logging.warning(f"Member not starting with 'm_': found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1

                    # Check for pointers starting with 'p'
                    for match in re.finditer(r'(?<!/)\*\s*\w+', line):
                        word = match.group()[1:].lstrip()
                        if not word.startswith('p'):
                            logging.warning(f"Pointer {word} is not starting with the letter 'p': found at line {line_number}")
                            self.counts['naming_conventions_check'] += 1

            logging.info(f"Naming conventions check completed - Count: {self.counts['naming_conventions_check']}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during naming conventions check: {str(e)}")

    def preprocess_cpp_file(self):
        processed_file_path = self.script_path.parent / f"{self.script_path.stem}_processed.cpp"
        try:
            command = ['cpp', '-o', str(processed_file_path), str(self.script_path)]
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during preprocessing: {e}")
            if e.stderr:
                logging.error(f"cpp error: {e.stderr}")
        except Exception as e:
            logging.error(f"Error during preprocessing: {str(e)}")

        return processed_file_path
    
    def check_modularization(self):
        try:
            with open(self.script_path, "r") as script_file:
                lines = script_file.readlines()

            repeated_sequences = {}
            # Create sequences of lines
            for start_index in range(len(lines) - SEQUENCE_LENGTH + 1):
                sequence = tuple(lines[start_index:start_index + SEQUENCE_LENGTH])
                if all(len(line.strip()) > 1 for line in sequence):  # Check if all lines have more than one character
                    if sequence in repeated_sequences:
                        repeated_sequences[sequence].append(start_index + 1)  # Line numbers start from 1
                    else:
                        repeated_sequences[sequence] = [start_index + 1]

            for sequence, line_numbers in repeated_sequences.items():
                if len(line_numbers) >= REPETITION_THRESHOLD and len(sequence) > 1:
                    # Remove leading and trailing whitespace from the sequence for better readability in the log
                    formatted_sequence = ''.join(sequence).strip()
                    warning_message = f"Repetition detected: Sequence '{formatted_sequence}' repeated {len(line_numbers)} times. Consider refactoring as a function. Lines: {', '.join(map(str, line_numbers))}"
                    logging.warning(warning_message)
                    self.counts['modularization_check'] += 1

            logging.info(f"Modularization check completed - Count: {self.counts['modularization_check']}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during modularization check: {str(e)}")

    def check_file_encoding(self):
        try:
            with open(self.script_path, 'rb') as f:
                encoding = ''
                for line in f:
                    try:
                        line.decode('utf-8')
                    except UnicodeDecodeError as e:
                        encoding = str(e)
                        logging.error(f"File is not UTF-8 encoded - Please save the file in UTF-8 Format: {e}")
                        if 'file_encoding_check' in self.counts:
                            self.counts['file_encoding_check'] += 1
                        else:
                            self.counts['file_encoding_check'] = 1
                        break
                if not encoding:
                    logging.info("File is UTF-8 encoded - Expected")

            if 'file_encoding_check' not in self.counts:
                self.counts['file_encoding_check'] = 0

            logging.info(f"File encoding check completed - Count: {self.counts['file_encoding_check']}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during file encoding check: {str(e)}")

    def check_consistency(self):
        try:
            with open(self.script_path, "r") as script_file:
                lines = script_file.readlines()

            # Check for consistent use of tabs or spaces for indentation
            indentation_type = None
            for line_number, line in enumerate(lines, start=1):
                try:
                    leading_whitespace = len(line) - len(line.lstrip())
                    if leading_whitespace < len(line):
                        if line[leading_whitespace] == '\t':
                            if indentation_type is None:
                                indentation_type = 'tabs'
                            elif indentation_type != 'tabs':
                                logging.warning(f"Inconsistent use of tabs and spaces for indentation at line {line_number}")
                                self.counts['consistency_check'] += 1
                        else:
                            if indentation_type is None:
                                indentation_type = 'spaces'
                            elif indentation_type != 'spaces':
                                logging.warning(f"Inconsistent use of tabs and spaces for indentation at line {line_number}")
                                self.counts['consistency_check'] += 1
                except IndexError as ie:
                    logging.error(f"IndexError at line {line_number}: {line} - {str(ie)}")
                    self.counts['consistency_check'] += 1

            # Check for consistent line endings (CRLF or LF)
            line_endings = set()
            for line_number, line in enumerate(lines, start=1):
                if '\r\n' in line:
                    line_endings.add('CRLF')
                elif '\n' in line:
                    line_endings.add('LF')

            if len(line_endings) > 1:
                logging.warning('Inconsistent line endings found in the script. Use either CRLF(line break "\r\n") or LF(line break "\n"), not both.')
                self.counts['consistency_check'] += 1

            logging.info(f"Consistency check completed - Count: {self.counts['consistency_check']}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during consistency check: {str(e)}")

    def check_excess_whitespace(self):
        try:
            with open(self.script_path, "r") as script_file:
                lines = script_file.readlines()

            for line_number, line in enumerate(lines, start=1):
                stripped_line = line.strip()
                if re.search(r'\\s{2,}', stripped_line):
                    logging.warning(f"Excess whitespace detected: Line {line_number} '{stripped_line}' has more than one space.")
                    self.counts['excess_whitespace_check'] += 1

            logging.info(f"Excess whitespace check completed - Count: {self.counts['excess_whitespace_check']}")

        except FileNotFoundError:
            logging.error(f"File not found: {self.script_path}")
        except Exception as e:
            logging.error(f"Error during excess whitespace check: {str(e)}")

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
        'total_lines_check': 'Line Count Verification',
        'indentation_check': 'Indentation Consistency Inspection',
        'naming_conventions_check': 'Naming Standards Assessment',
        'modularization_check': 'Module Structure Evaluation',
        'consistency_check': 'Code Uniformity Check',
        'excess_whitespace_check': 'Whitespace Reduction Analysis',
        'file_encoding_check':'File Format Consistency Verification'
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
    script_analyzer = ScriptAnalyzer(script_path, recipient_email, sender_email, sender_password)
    script_analyzer.run_analysis()