batch_size = 3
count = 0
total_fail = 0
total_pass = 0
critical_count = 0
#Count initalized before the code to see how many times the code has to run
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

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    #This checks how often you are changing your password per number of months
    if rotation_interval > 12:
        rotational_verdict = "WARNING - rotation interval exceeds recommended maximum of 12 months"
    elif 6 <= rotation_interval <= 12:
        rotational_verdict = "ACCEPTABLE — rotation interval within recommended range"
    elif rotation_interval < 6:
        rotational_verdict = "EXCELLENT — frequent rotation policy detected"

    #This checks if username & password are the same.
    #Had to make a different varaible for it not to print True or False.
    not_username = password != username
    if not_username == False:
        username_match = "CRTICAL - password must not match username"
        critical_count += 1
    else:
        username_match = "NO"

    #This checks if the password has any digits in it and prints if it does or not
    #has_digit = '0' in password or '1' in password or '2' in password or '3' in password or '4' in password or '5' in password or '6' in password or '7' in password or '8' in password or '9' in password

    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

    if has_digit == True:
        digit_found = "YES"
    else:
        digit_found = "NO"


    #This checks the password length in your password and lets you know how strong/weak it is
    if password_length < 8:
        length_verdict = "WEAK — does not meet minimum length requirements"
    elif 8 <= password_length <= 11:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
    elif  12 <= password_length <= 14:
        length_verdict = "GOOD — acceptable length for most systems"
    elif  password_length > 15:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

    #This combines varaibles into one to see if your password meets all the criteria for a strong password
    length_ok = password_length >= 15
    overall_pass = length_ok and has_digit and not_username
    if overall_pass == True:
        overall = "OVERALL: PASS - password meets all checked criteria"
        total_pass += 1
    else:
        overall = "OVERALL: FAIL - see findings above"
        total_fail += 1

    count += 1
    #This code prints your report at the end based on the data the user inputted
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
    print(f"Digit found:       {digit_found}")
    print(f"Username match:    {username_match}")
    print(f"Rotation verdict:  {rotational_verdict}")
    print("----------------------------------------")
    print("========================================")
    print("--------- BATCH AUDIT SUMMARY ---------")
    print("========================================")
    print(f"Passwords audited: {count}")
    print(f"Passed: {total_pass}")
    print(f"Failed: {total_fail}")
    print(f"Critical Flags: {critical_count}")
    print("----------------------------------------")
    print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
    print("========================================")
    print(overall)
    print("= = = = = = = = = = = = = = = = = = = = =")