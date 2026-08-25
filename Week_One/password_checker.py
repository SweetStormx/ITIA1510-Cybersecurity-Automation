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
print("NOTE: Classification requires conditionals -- coming in Week 02.")
print("========================================")