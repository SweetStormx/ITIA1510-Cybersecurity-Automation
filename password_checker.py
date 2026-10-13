
#This list is the known breached passwords that are easily guessed
#This list is outside of the main block so check_breach can access the list and the test file can import it

#The policy is outside main so other files can import and use the policy settings
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}

def load_credentials(filepath):
    """Read credentials from a comma-separated text file."""
    credentials = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines before splitting the fields.
            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })

    return credentials

def load_breached(filepath):
    """Read the breached password file and return a list."""
    known_breached = []

    # with closes the file automatically when the block ends.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines so they are not treated as passwords.
            if line == "":
                continue

            known_breached.append(line)

    return known_breached

def write_report(report_lines, filepath):
    """Write each report line to a text file."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")

#This function checks if any of the passwords have been breached
def check_breach(password, known_breached):
    #the in operator checks whether a value exists anywhere in the list
    #a loop would walk through each item individually instead
    not_breached = password not in known_breached
    return not_breached

#This function checks how often the password is rotated via months
def check_rotation(rotation_interval, policy):
        #This checks how often you are changing your password per number of months
        if rotation_interval > policy["max_rotation_months"]:
            rotational_verdict = "WARNING - rotation interval exceeds recommended maximum of 12 months"
            rotation_ok = False
        elif policy["good_rotation_months"] <= rotation_interval <= policy["max_rotation_months"]:
            rotational_verdict = "ACCEPTABLE — rotation interval within recommended range"
            rotation_ok = True
        elif rotation_interval < policy["good_rotation_months"]:
            rotational_verdict = "EXCELLENT — frequent rotation policy detected"
            rotation_ok = True
        return rotation_ok, rotational_verdict

#This function checks if the username & password match
def check_username(password, username):
        not_username = password != username
        if not_username == False:
            username_match = "CRTICAL - password must not match username"
        else:
            username_match = "NO"
        return not_username, username_match

#This function checks if there are any digits in the password
def check_digit(password):
        has_digit = False
        for char in password:
            if char in '0123456789':
                has_digit = True
        return has_digit

#Reading the limit from policy keeps the value in one place instead of repeating 
#the number in each function
def check_length(password, policy):

    password_length = len(password)

    if password_length < policy["min_length"]:
        length_verdict = "WEAK — does not meet minimum length requirements"
        length_ok = False

    elif password_length >= policy["strong_length"]:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"
        length_ok = True

    else:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
        length_ok = True

    return length_ok, length_verdict


def audit_password(account, username, password, rotation_interval, known_breached, policy, report_lines, report_number):
    #This will run the four password checks
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username, username_match = check_username(password, username)
    rotation_ok, rotational_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    #Calculate info for report
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval


    #Overall Result
    overall_pass = length_ok and has_digit and not_username and not_breached

    if overall_pass:
         overall = "OVERALL: PASS - password meets all checked criteria"
         passed = 1
         failed = 0
    else:
         overall = "OVERALL: FAIL - see findings above"
         passed = 0
         failed = 1

    #Username and Password match check
    if not_username == False or not_breached == False:
         critical = 1
    else:
         critical = 0

    digit_result = "YES" if has_digit else "NO"

    if not_breached:
        breach_result = "NO KNOWN BREACH"
    else:
        breach_result = "CRITICAL -- password found in known breach list"

    #Print password report
    report_lines.append("========================================")
    report_lines.append(f"   PASSWORD AUDIT REPORT   ({report_number} of 5)")
    report_lines.append("========================================")
    report_lines.append(f"Account:           {account}")
    report_lines.append(f"Username:          {username}")
    report_lines.append(f"Password length:   {password_length} characters")
    report_lines.append(f"Length score:      {length_score} points")
    report_lines.append(f"Rotation interval: {rotation_interval} months")
    report_lines.append(f"Rotations (3 yr):  {rotation_count}")
    report_lines.append("----------------------------------------")
    report_lines.append(f"Length Verdict:    {length_verdict}")
    report_lines.append(f"Digit found:       {has_digit}")
    report_lines.append(f"Username match:    {username_match}")
    report_lines.append(f"Rotation verdict:  {rotational_verdict}")
    report_lines.append(f"Breach Check: {not_breached}")
    report_lines.append("----------------------------------------")
    report_lines.append(overall)
    report_lines.append("========================================")
    report_lines.append("= = = = = = = = = = = = = = = = = = = = =")

    return passed, failed, critical

if __name__ == '__main__':

    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []
    #{"account": "Gmail", "username": "hCole", "password": "dragon", "rotation_interval": 12},
    #{"account": "Outlook", "username": "hCole", "password": "hCole", "rotation_interval": 24},
    #{"account": "VPN", "username": "hCole", "password": "Tr0ub4dor&3correct", "rotation_interval": 3},
    #{"account": "Company Email", "username": "hCole", "password": "summer2024!", "rotation_interval": 6},
    #{"account": "GitHub", "username": "hCole", "password": "Red-Coast-27-Torch", "rotation_interval": 6},

    count = 0
    summary = {"total": 0, "passed": 0, "failed": 0, "critical": 0,
           "failed_accounts": [], "critical_accounts": []}

    failed_accounts = []
    critical_accounts = []


    for report_number, cred in enumerate(credentials, start=1):
        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            report_lines,
            report_number
    )

    summary["total"] += 1
    summary["passed"] += passed
    summary["failed"] += failed
    summary["critical"] += critical

    if failed:
        summary["failed_accounts"].append(cred["account"])

    if critical:
        summary["critical_accounts"].append(cred["account"])

        
    for line in report_lines:
             print(line)

    def write_report(report_lines, filepath):
    #"""Write each report line to a text file."""
        with open(filepath, "w") as f:
            for line in report_lines:
                f.write(line + "\n")

    #Batch Summary
    report_lines.append("========================================")
    report_lines.append("-----------BATCH AUDIT SUMMARY----------")
    report_lines.append("========================================")
    report_lines.append(f"Credentials audited: {summary['total']}")
    report_lines.append(f"Passed: {summary['passed']}")
    report_lines.append(f"Failed: {summary['failed']}")
    report_lines.append("----------------------------------------")
    report_lines.append(f"Failed accounts: {failed_accounts}")
    report_lines.append(f"Critical Flags: {summary['critical']}")
    report_lines.append(f"Critical Accounts: {critical_accounts}")
    report_lines.append("----------------------------------------")
    report_lines.append("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08")
    report_lines.append("========================================")

    for line in report_lines:
        print(line)
    write_report(report_lines, "report.txt")
