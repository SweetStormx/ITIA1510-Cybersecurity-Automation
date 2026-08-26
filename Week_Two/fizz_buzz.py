# If int divisible by 3, print fizz
# If int divisible by 5, print buzz
# If int divisible by 3 and 5, print fizz buzz

#Get user response & convert str to int
response = input("Pick a number: ")
response = int(response)

#user response divisible by 3 and/or 5, '==0' for remainder!
if response % 3 == 0 and response % 5 == 0:
    print("Fizz Buzz")
elif response % 3 == 0:
    print("Fizz")
elif response % 5 == 0:
    print("Buzz")
else:
    print("Try Again :p")