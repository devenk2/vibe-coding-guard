# Intentionally vulnerable Python file for testing Vibe Coding Guard
# DO NOT use this code in production

import os
import pickle
import subprocess
import hashlib
import yaml
import sqlite3
import requests

# HIGH: eval usage
user_input = input("Enter expression: ")
result = eval(user_input)

# HIGH: exec usage
code_string = "print('hello')"
exec(code_string)

# HIGH: os.system command injection
filename = input("Enter filename: ")
os.system("cat " + filename)

# HIGH: pickle deserialization
data = open("data.pkl", "rb").read()
obj = pickle.loads(data)

# HIGH: subprocess with shell=True
cmd = input("Enter command: ")
subprocess.run(cmd, shell=True)

# HIGH: SQL injection via string concatenation
conn = sqlite3.connect("test.db")
cursor = conn.cursor()
user_id = input("Enter user ID: ")
cursor.execute("SELECT * FROM users WHERE id=" + user_id)

# HIGH: SQL injection via f-string
name = input("Enter name: ")
cursor.execute(f"SELECT * FROM users WHERE name='{name}'")

# HIGH: Hardcoded secret
api_key = "sk-1234567890abcdef1234567890abcdef"
password = "SuperSecretPassword123!"
database_url = "postgresql://admin:secretpass123@localhost/mydb"

# MEDIUM: Weak crypto
hash_md5 = hashlib.md5(b"data")
hash_sha1 = hashlib.sha1(b"data")

# MEDIUM: SSL verification disabled
response = requests.get("https://api.example.com", verify=False)

# MEDIUM: Unsafe YAML loading
with open("config.yaml") as f:
    config = yaml.load(f)

# LOW: Bare except
try:
    risky_operation()
except:
    pass

# LOW: Exception swallowing
try:
    another_risky_operation()
except Exception:
    pass
