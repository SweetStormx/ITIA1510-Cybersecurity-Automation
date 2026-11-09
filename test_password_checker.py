import json
from password_checker import load_credentials, load_breached, write_report, check_breach, check_rotation, check_username, check_digit, check_length, audit_password, save_summary, load_summary, load_history, add_to_history, save_history, breach_verdicts, length_verdicts, rotation_verdicts, run_check, CHECK_NAMES, policy

known_breached = load_breached("breached.txt")
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


# Test 1: A missing history file returns an empty list.
assert load_history("missing_history_test.json") == []
print("PASS: missing history file returns an empty list")


# Test 2: The first history entry has run number 1.
history = []
history = add_to_history(history, sample, 3)

assert len(history) == 1
assert history[0]["run"] == 1
print("PASS: first history run is numbered 1")


# Test 3: Only the newest runs are kept.
history = []

for i in range(3):
    history = add_to_history(history, sample, 2)

assert [entry["run"] for entry in history] == [2, 3]
print("PASS: add_to_history kept only the newest 2 runs")


# Test 4: Saved history loads back unchanged.
save_history(history, "test_history.json")
assert load_history("test_history.json") == history
print("PASS: save_history and load_history returned the same history")

# BREACH VERDICTS
result18 = breach_verdicts("hCole", credentials, known_breached)
assert result18["accounts"][0] == {"account": "Gmail", "on_breach_list": True}
print("PASS: breach_verdicts marked the Gmail password as on the breach list")

result19 = breach_verdicts("nobody", credentials, known_breached)
assert result19["accounts"] == []
print("PASS: breach_verdicts returns an empty accounts list for a username with no accounts")

# Convert the verdict to JSON so the test checks every part of the returned result.
result20 = breach_verdicts("hCole", credentials, known_breached)
verdict_text = json.dumps(result20)
for credential in credentials:
    # The username is part of the result, so allow it when it also happens to be a password.
    if credential["password"] != credential["username"]:
        assert credential["password"] not in verdict_text
print("PASS: breach_verdicts does not include passwords in its result")


# WEEK 12: LENGTH VERDICTS
length_result = length_verdicts("hCole", credentials, known_breached)
assert length_result["accounts"][2] == {"account": "VPN", "long_enough": True}
print("PASS: length_verdicts reports the VPN password meets the length policy")

# WEEK 12: ROTATION VERDICTS
rotation_result = rotation_verdicts("hCole", credentials, known_breached)
assert rotation_result["accounts"][1] == {
    "account": "Outlook", "rotation_months": 24, "rotation_ok": False
}
print("PASS: rotation_verdicts flags Outlook's 24-month rotation interval")

# CHECK_NAMES must use the exact strings handled by run_check().
assert CHECK_NAMES == ["check_breach", "check_length", "check_rotation"]
print("PASS: CHECK_NAMES contains the three supported check names")

# run_check should return the same result as calling the selected function directly.
assert run_check("check_breach", "hCole", credentials, known_breached) == breach_verdicts(
    "hCole", credentials, known_breached
)
print("PASS: run_check dispatches the breach check correctly")

# Unsupported names must return an error instead of running a different check.
assert run_check("reset_password", "hCole", credentials, known_breached) == {"error": "unknown check"}
print("PASS: run_check rejects an unknown check name")
