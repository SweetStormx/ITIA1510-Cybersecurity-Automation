
from password_checker import check_length, check_digit, check_username, check_rotation, check_breach, known_breached, policy

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