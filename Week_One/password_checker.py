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

def check_username(password, username):
        not_username = password != username
        if not_username == False:
            username_match = "CRTICAL - password must not match username"
        else:
            username_match = "NO"
        return not_username, username_match

def check_digit(password):
        has_digit = False
        for char in password:
            if char in '0123456789':
                has_digit = True
        return has_digit

def check_length(password):
        password_length = len(password)
        #This checks the password length in your password and lets you know how strong/weak it is
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

def audit_password(account, username, password, rotation_interval):
    #This will run the four password checks
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username, username_match = check_username(password, username)
    rotation_ok, rotational_verdict = check_rotation(rotation_interval)

    #Calculate info for report
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    #Overall Result
    overall_pass = length_ok and has_digit and not_username

    if overall_pass:
         overall = "OVERALL: PASS - password meets all checked criteria"
         passed = 1
         failed = 0
    else:
         overall = "OVERALL: FAIL - see findings above"
         passed = 0
         failed = 1

    #Username and Password match check
    if not_username == False:
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
    print("----------------------------------------")
    print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
    print("========================================")
    print(overall)
    print("= = = = = = = = = = = = = = = = = = = = =")

    return passed, failed, critical
if __name__ == '__main__':
    batch_size = 3
    count = 0
    total_fail = 0
    total_pass = 0
    critical_count = 0
    while count < batch_size:

        #Collect information from user
        print("What is the account name? Ex. email, discord, etc.")
        account = input()
        print("What is the username of the account?")
        username = input()
        print("what is your password?")
        password = input()

        rotation_interval = input("Password rotation interval (months): ")
        rotation_interval = int(rotation_interval)

        #Audit this password
        passed, failed, critical = audit_password(
             account, username, password, rotation_interval
        )

        #Batch counters update
        total_pass += passed
        total_fail += failed
        critical_count += critical

        count += 1

#Batch Summary
print("========================================")
print("-----------BATCH AUDIT SUMMARY----------")
print("========================================")
print(f"Passwords audited: {count}")
print(f"Passed: {total_pass}")
print(f"Failed: {total_fail}")
print(f"Critical Flags: {critical_count}")
print("----------------------------------------")
print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
print("========================================")