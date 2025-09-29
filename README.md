# PyAES-Crypt Encrypted File Cracker

A Python tool for cracking AES-encrypted files using wordlist-based password attacks. Supports files encrypted with pyAesCrypt.

## Features

- Wordlist-based password cracking for .aes files
- Real-time progress tracking
- Supports large wordlists (e.g., rockyou.txt)

## Requirements

```bash
pip install pyAesCrypt
```

## Usage

```bash
python3 aes_crack.py <encrypted_file.aes> -w <wordlist.txt> -o <output_file>
```

### Examples

```bash
python3 aes_crack.py backup.aes -w /usr/share/wordlists/rockyou.txt -o decrypted.zip

python3 aes_crack.py database.aes -w wordlist.txt -o recovered_data
```

## How It Works

1. Reads passwords from the provided wordlist
2. Attempts to decrypt the .aes file with each password
3. Stops when the correct password is found
4. Saves the decrypted file to the specified output location

## Output

The tool provides:
- Real-time password attempt counter
- Cracking speed (passwords/second)
- Successful password when found
- Time statistics

## Performance

Typical cracking speed varies based on hardware but generally ranges from 50-200 passwords per second on modern systems.

## Legal Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for ensuring they have permission to decrypt any files they target with this tool.

## License

MIT License
