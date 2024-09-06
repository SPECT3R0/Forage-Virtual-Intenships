from zipfile import ZipFile, BadZipFile
import sys

# Function to attempt extraction with a given password
def attempt_extract(zf_handle, password):
    try:
        # Try to extract using the password
        zf_handle.extractall(pwd=password.strip())
        print(f"[+] Password found: {password.decode().strip()}")
        return True
    except (RuntimeError, BadZipFile):
        # Bad password, continue brute-forcing
        return False

def main():
    print("[+] Beginning bruteforce...")
    
    with ZipFile('enc.zip') as zf:  # Open the zip file
        with open('rockyou.txt', 'rb') as f:  # Open the wordlist in binary mode
            for password in f:  # Iterate through passwords
                if attempt_extract(zf, password):  # Try to extract the ZIP file
                    break  # Stop if the password is found
            else:
                print("[+] Password not found in list")

if __name__ == "__main__":
    main()
