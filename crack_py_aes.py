#!/usr/bin/env python3

import sys
import os
import time
import argparse

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

def crack_aes_file(encrypted_file, wordlist_file, output_file):
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
    print(f"[+] Target: {encrypted_file}")
    print(f"[+] Wordlist: {wordlist_file}")
    print(f"[+] Output: {output_file}")
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
                    print(f"[{attempt_count:6d}] {rate:6.1f} pwd/s", end='\r')
                
                decrypted_data = try_decrypt_pyaescrypt(encrypted_file, password)
                
                if decrypted_data:
                    elapsed_time = time.time() - start_time
                    print("\n" + "="*60)
                    print("[+] SUCCESS")
                    print("="*60)
                    print(f"[+] Password: {password}")
                    print(f"[+] Attempts: {attempt_count}")
                    print(f"[+] Time: {elapsed_time:.2f}s")
                    print(f"[+] Rate: {attempt_count/elapsed_time:.1f} pwd/s")
                    
                    with open(output_file, 'wb') as out:
                        out.write(decrypted_data)
                    print(f"[+] Decrypted file saved: {output_file}")
                    print("="*60)
                    return True
        
        elapsed_time = time.time() - start_time
        print(f"\n[-] Password not found ({attempt_count} attempts, {elapsed_time:.2f}s)")
        return False
        
    except KeyboardInterrupt:
        elapsed_time = time.time() - start_time
        print(f"\n[-] Interrupted ({attempt_count} attempts, {elapsed_time:.1f}s)")
        return False
    except Exception as e:
        print(f"\n[-] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='AES-Crypt wordlist cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python3 aes_crack.py encrypted.aes -w rockyou.txt -o decrypted.zip'
    )
    
    parser.add_argument('encrypted_file', help='Encrypted .aes file')
    parser.add_argument('-w', '--wordlist', required=True, help='Password wordlist')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    
    args = parser.parse_args()
    
    success = crack_aes_file(args.encrypted_file, args.wordlist, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
