# A fast and simple hash cracker.
# Works on (MD5, SHA1, SHA256, SHA224, SHA224, SHA512)
# Does not work on salted hashes.

# [?] USAGE: python3 hashCrack.py <hash type> <wordlist> <target hash>

import hashlib
import sys

RED, REGULAR, GREEN, YELLOW = '\33[31m', '\33[37m', '\33[32m', '\33[33m'

hash_type = str(sys.argv[1])
file_path = str(sys.argv[2])
target_hash = str(sys.argv[3])

with open(file_path, 'r') as file:
    print(f"\n[+] Cracking....")
    for line in file.readlines():
        if hash_type == 'md5':
            password = hashlib.md5(line.strip().encode())
            hashed_password = password.hexdigest()
            if hashed_password == target_hash:
                print(f"[+] {GREEN}Successfully cracked: {target_hash}: {YELLOW}{line.strip()}")
                exit(0)

        if hash_type == 'sha1':
            password = hashlib.sha1(line.strip().encode())
            hashed_password = password.hexdigest()
            if hashed_password == target_hash:
                print(f"[+] {GREEN}Successfully cracked: {target_hash}: {YELLOW}{line.strip()}")
                exit(0)

        if hash_type == 'sha256':
            password = hashlib.sha256(line.strip().encode())
            hashed_password = password.hexdigest()
            if hashed_password == target_hash:
                print(f"[+] {GREEN}Successfully cracked: {target_hash}: {YELLOW}{line.strip()}")
                exit(0)

        if hash_type == 'sha384':
            password = hashlib.sha384(line.strip().encode())
            hashed_password = password.hexdigest()
            if hashed_password == target_hash:
                print(f"[+] {GREEN}Successfully cracked: {target_hash}: {YELLOW}{line.strip()}")
                exit(0)

        if hash_type == 'sha512':
            password = hashlib.sha512(line.strip().encode())
            hashed_password = password.hexdigest()
            if hashed_password == target_hash:
                print(f"[+] {GREEN}Successfully cracked: {target_hash}: {YELLOW}{line.strip()}")
                exit(0)

        if hash_type == 'sha224':
            password = hashlib.sha224(line.strip().encode)
            hashed_password = password.hexdigest()
            if hashed_password == target_hash:
                print(f"[+]{GREEN}Successfully cracked: {target_hash}: {YELLOW}{line.strip()}")
                exit(0)
    print(f"{RED}[-] Could not match the hash, try a different Wordlist")
