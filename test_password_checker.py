
from password_checker import check_length, check_digit, check_username, check_rotation, check_breach,load_credentials, load_breached, write_report, policy, save_summary, load_summary
known_breached = load_breached("breached.txt")
#DIGIT
result1 = check_digit("hello")
assert result1 == False
print("PASS: check_digit correctly identified password with no digit")

result2 = check_digit("hello5")
assert result2 == True
print("PASS: check_digit correctly identified password with a digit")

#LENGTH
result3 = check_length("abcdefghijklmnopqrstuvwxyz", policy)
assert result3[0] == True
print("PASS: check_length correctly identified password with 15+ characters")

result4 = check_length("abc", policy)
assert result4[0] == False
print("PASS: check_length correctly identified password with less than 15 characters")

#USERNAME
result5 = check_username('one','one')
assert result5[0] == False
print("PASS: check_username correctly identified that password and username match")

result6 = check_username('one', 'two')
assert result6[0] == True
print("PASS: check_username correctly identified that password and username do not match")

#ROTATION
result7 = check_rotation(36, policy)
assert result7[0] == False
print("PASS: check_rotation correctly identified that rotation unsafe")

result8 = check_rotation(3, policy)
assert result8[0] == True
print("PASS: check_rotation correctly identified that rotation safe")

result9 = check_breach("dragon", known_breached)
assert result9 == False
print("PASS: check_breach correctly identified a breached password")

result10 = check_breach("ThisIsASuperSecuredPasswordLOL123!", known_breached)
assert result10 == True
print("PASS: check_breach correctly identified password not in the breach list")

result11 = policy["strong_length"]
assert result11 == 15
print("PASS: policy strong_length is set to 15")

result12 = "require_digit" in policy
assert result12 == True
print("PASS: policy contains require_digit")

credentials = load_credentials("credentials.txt")
result13 = isinstance(credentials, list)
assert result13 == True
print("PASS: load_credentials returns a list")


result14 = "account" in credentials[0]
assert result14 == True
print("PASS: first credential contains account key")


result15 = isinstance(known_breached, list)
assert result15 == True
print("PASS: load_breached returns a list")


result16 = "password123" in known_breached
assert result16 == True
print("PASS: breached list contains password123")

test_lines = ["First test line", "Second test line"]
write_report(test_lines, "test_report.txt")

with open("test_report.txt", "r") as f:
    report_text = f.read()

result17 = report_text == "First test line\nSecond test line\n"

assert result17 == True

print("PASS: write_report saves the correct text")

# Test 1: The saved dictionary matches the original.
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"]
}

save_summary(sample, "test_summary.json")
assert load_summary("test_summary.json") == sample
print("PASS: save_summary and load_summary gave back the same dictionary")


# Test 2: failed_accounts is a list.
loaded = load_summary("test_summary.json")
assert isinstance(loaded["failed_accounts"], list)
print("PASS: failed_accounts is a list")


# Test 3: No password appears in the saved JSON file.
with open("test_summary.json", "r") as f:
    saved_text = f.read()

with open("credentials.txt", "r") as f:
    credentials = load_credentials("credentials.txt")

# Check every actual password against the saved file.
for credential in credentials:
    password = credential["password"]
    assert password not in saved_text

print("PASS: no passwords appear in the saved summary")