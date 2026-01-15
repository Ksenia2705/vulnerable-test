import os
import subprocess

# CWE-798: Hardcoded credentials
password = "admin123"
api_key = "sk-1234567890abcdef"
db_password = "P@ssw0rd!"

# CWE-89: SQL Injection
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

# CWE-78: Command Injection
def ping_host(hostname):
    os.system("ping -c 1 " + hostname)
    
def run_command(cmd):
    subprocess.call("ls " + cmd, shell=True)

# CWE-22: Path Traversal
def read_file(filename):
    path = "/var/data/" + filename
    with open(path, 'r') as f:
        return f.read()

# CWE-502: Insecure Deserialization
import pickle
def load_data(data):
    return pickle.loads(data)

# CWE-327: Weak Crypto
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
