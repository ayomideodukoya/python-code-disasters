import os

# Insecure use of `os.system` (Command Injection Vulnerability)
user_input = input("Enter command: ")
os.system(user_input)  # UNSAFE

# Hardcoded secret (Sensitive Information Disclosure)
API_KEY = "sk_live_1234567890abcdef"
