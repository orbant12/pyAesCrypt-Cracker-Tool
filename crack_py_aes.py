#!/usr/bin/env python3

import sys
import os
import time
import json
import zipfile
from pathlib import Path

def try_decrypt_pyaescrypt(encrypted_file, password):
    try:
        import pyAesCrypt
        from io import BytesIO
        
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        input_stream = BytesIO(encrypted_data)
        output_stream = BytesIO()
        
        bufferSize = 64 * 1024
        pyAesCrypt.decryptStream(input_stream, output_stream, password, bufferSize)
        
        output_stream.seek(0)
        return output_stream.read()
        
    except Exception as e:
        return None

def extract_and_parse_zip(decrypted_data, output_dir="extracted"):
    try:
        from io import BytesIO
        
        with open("temp_decrypted.zip", "wb") as f:
            f.write(decrypted_data)
        
        os.makedirs(output_dir, exist_ok=True)
        with zipfile.ZipFile("temp_decrypted.zip", 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        
        print(f"\n[+] Archive extracted to: {output_dir}")
        print("[+] Contents:")
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                filepath = os.path.join(root, file)
                print(f"    - {filepath}")
        
        db_json_path = None
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith('db.json'):
                    db_json_path = os.path.join(root, file)
                    break
        
        if db_json_path:
            print(f"\n[+] Found db.json at: {db_json_path}")
            try:
                with open(db_json_path, 'r') as f:
                    db_data = json.load(f)
                
                print("\n[+] db.json contents:")
                print(json.dumps(db_data, indent=2))
                
                print("\n[+] Searching for credentials and hashes...")
                search_keys = ['password', 'hash', 'passwd', 'pwd', 'credential', 'secret', 'token', 'key', 'user', 'username', 'admin']
                
                def search_dict(d, prefix=""):
                    findings = []
                    if isinstance(d, dict):
                        for key, value in d.items():
                            if any(search_key in key.lower() for search_key in search_keys):
                                findings.append(f"{prefix}{key}: {value}")
                            if isinstance(value, (dict, list)):
                                findings.extend(search_dict(value, f"{prefix}{key}."))
                    elif isinstance(d, list):
                        for i, item in enumerate(d):
                            findings.extend(search_dict(item, f"{prefix}[{i}]."))
                    return findings
                
                findings = search_dict(db_data)
                if findings:
                    print("\n[!] POTENTIAL CREDENTIALS FOUND:")
                    for finding in findings:
                        print(f"    {finding}")
                else:
                    print("    No obvious credential fields found")
                    
            except json.JSONDecodeError:
                print("[!] db.json found but could not be parsed as JSON")
            except Exception as e:
                print(f"[!] Error reading db.json: {e}")
        else:
            print("\n[!] No db.json found in archive")
        
        os.remove("temp_decrypted.zip")
        
        return True
        
    except zipfile.BadZipFile:
        print("[!] Decrypted file is not a valid ZIP archive")
        return False
    except Exception as e:
        print(f"[!] Error extracting/parsing archive: {e}")
        return False

def crack_aes_file(encrypted_file, wordlist_file, output_file="decrypted.zip"):
    if not os.path.exists(encrypted_file):
        print(f"[-] Encrypted file not found: {encrypted_file}")
        return False
    
    if not os.path.exists(wordlist_file):
        print(f"[-] Wordlist not found: {wordlist_file}")
        return False
    
    try:
        import pyAesCrypt
    except ImportError:
        print("[-] pyAesCrypt not found. Installing...")
        try:
            import subprocess
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyAesCrypt'])
            import pyAesCrypt
        except:
            print("[-] Failed to install pyAesCrypt")
            return False
    
    print("="*60)
    print("AES-Crypt Wordlist Cracker")
    print("="*60)
    print(f"[+] Target file: {encrypted_file}")
    print(f"[+] Wordlist: {wordlist_file}")
    print(f"[+] File size: {os.path.getsize(encrypted_file)} bytes")
    print("-"*60)
    
    start_time = time.time()
    attempt_count = 0
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                attempt_count += 1
                
                if attempt_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = attempt_count / elapsed if elapsed > 0 else 0
                    print(f"[{attempt_count:6d}] Rate: {rate:6.1f} pwd/s | Last: {password[:30]}", end='\r')
                
                decrypted_data = try_decrypt_pyaescrypt(encrypted_file, password)
                
                if decrypted_data:
                    elapsed_time = time.time() - start_time
                    print("\n" + "="*60)
                    print("[+] PASSWORD CRACKED!")
                    print("="*60)
                    print(f"[+] Password: {password}")
                    print(f"[+] Attempts: {attempt_count}")
                    print(f"[+] Time: {elapsed_time:.2f} seconds")
                    print(f"[+] Rate: {attempt_count/elapsed_time:.1f} passwords/sec")
                    print(f"[+] Decrypted size: {len(decrypted_data)} bytes")
                    
                    with open(output_file, 'wb') as out:
                        out.write(decrypted_data)
                    print(f"[+] Saved to: {output_file}")
                    
                    print("\n" + "-"*60)
                    print("[*] Attempting to extract archive...")
                    extract_and_parse_zip(decrypted_data)
                    
                    print("="*60)
                    return True
        
        elapsed_time = time.time() - start_time
        print(f"\n[-] Password not found after {attempt_count} attempts")
        print(f"[-] Time elapsed: {elapsed_time:.2f} seconds")
        return False
        
    except KeyboardInterrupt:
        elapsed_time = time.time() - start_time
        print(f"\n[-] Interrupted after {attempt_count} attempts ({elapsed_time:.1f}s)")
        return False
    except Exception as e:
        print(f"\n[-] Error: {e}")
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 aes_crack.py <encrypted_file.aes> <wordlist.txt> [output.zip]")
        print("\nExample:")
        print("  python3 aes_crack.py backup.aes /usr/share/wordlists/rockyou.txt")
        sys.exit(1)
    
    encrypted_file = sys.argv[1]
    wordlist_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else "decrypted.zip"
    
    success = crack_aes_file(encrypted_file, wordlist_file, output_file)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
