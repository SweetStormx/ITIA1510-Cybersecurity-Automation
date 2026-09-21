
#This list is the known breached passwords that are easily guessed
#This list is outside of the main block so check_breach can access the list and the test file can import it
known_breached = ["password", "password123", "123456", "qwerty", "letmein",
                  "welcome", "monkey", "dragon", "master", "sunshine"]

#This function checks if any of the passwords have been breached
def check_breach(password, known_breached):
    #the in operator checks whether a value exists anywhere in the list
    #a loop would walk through each item individually instead
    not_breached = password not in known_breached
    return not_breached

#This function checks how often the password is rotated via months
def check_rotation(rotation_interval):
        #This checks how often you are changing your password per number of months
        if rotation_interval > 12:
            rotational_verdict = "WARNING - rotation interval exceeds recommended maximum of 12 months"
            rotation_ok = False
        elif 6 <= rotation_interval <= 12:
            rotational_verdict = "ACCEPTABLE — rotation interval within recommended range"
            rotation_ok = True
        elif rotation_interval < 6:
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

#This function checks the length of the password
#The length_ok checks if the password length will be strong enough
def check_length(password):
        password_length = len(password)
        if password_length < 8:
            length_verdict = "WEAK — does not meet minimum length requirements"
            length_ok = False
        elif 8 <= password_length <= 11:
            length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
            length_ok = False
        elif  12 <= password_length <= 14:
            length_verdict = "GOOD — acceptable length for most systems"
            length_ok = False
        elif  password_length >= 15:
            length_verdict = "STRONG — meets NIST SP 800-63B recommendations"
            length_ok = True
        return length_ok, length_verdict

def audit_password(account, username, password, rotation_interval, known_breached):
    #This will run the four password checks
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username, username_match = check_username(password, username)
    rotation_ok, rotational_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    #Calculate info for report
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    if not_breached:
        print("Password not found in known breach list")
    else:
        print("CRITICAL -- password found in known breach list")

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

    #Print password report
    print("========================================")
    print("   PASSWORD AUDIT REPORT")
    print("========================================")
    print(f"Account:           {account}")
    print(f"Username:          {username}")
    print(f"Password length:   {password_length} characters")
    print(f"Length score:      {length_score} points")
    print(f"Rotation interval: {rotation_interval} months")
    print(f"Rotations (3 yr):  {rotation_count}")
    print("----------------------------------------")
    print(f"Length Verdict:    {length_verdict}")
    print(f"Digit found:       {has_digit}")
    print(f"Username match:    {username_match}")
    print(f"Rotation verdict:  {rotational_verdict}")
    print(f"Breach Check: {not_breached}")
    print("----------------------------------------")
    print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
    print("========================================")
    print(overall)
    print("= = = = = = = = = = = = = = = = = = = = =")

    return passed, failed, critical


if __name__ == '__main__':

    credentials = [
    ["Gmail", "hCole", "dragon", 12],
    ["Outlook", "hCole", "hCole", 24],
    ["VPN", "hCole", "Tr0ub4dor&3correct", 3],
    ["Company Email", "hCole", "summer2024!", 6],
    ["GitHub", "hCole", "Red-Coast-27-Torch", 6],
    ]

    count = 0
    total_fail = 0
    total_pass = 0
    critical_count = 0

    failed_accounts = []
    critical_accounts = []

    for credential in credentials:
        account, username, password, rotation_interval = credential

        passed, failed, critical = audit_password(
            account, username, password, rotation_interval, known_breached
        )
        if failed:
             failed_accounts.append(account)
        if critical:
             critical_accounts.append(account)

        total_pass += passed
        total_fail += failed
        critical_count += critical

        count += 1


    #Batch Summary
    print("========================================")
    print("-----------BATCH AUDIT SUMMARY----------")
    print("========================================")
    print(f"Credentials audited: {count}")
    print(f"Passed: {total_pass}")
    print(f"Failed: {total_fail}")
    print("----------------------------------------")
    print(f"Failed accounts: {failed_accounts}")
    print(f"Critical Flags: {critical_count}")
    print(f"Critical Accounts: {critical_accounts}")
    print("----------------------------------------")
    print("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08")
    print("========================================")