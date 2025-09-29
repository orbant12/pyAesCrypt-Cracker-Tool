# AES-Crypt Wordlist Cracker

A Python tool for cracking AES-encrypted files using wordlist-based password attacks. Supports files encrypted with pyAesCrypt and automatically extracts and parses JSON data from recovered archives.

## Features

- Wordlist-based password cracking for .aes files
- Automatic ZIP archive extraction
- JSON data parsing and credential extraction
- Real-time progress tracking
- Supports large wordlists (e.g., rockyou.txt)

## Requirements

```bash
pip install pyAesCrypt
```

## Usage

```bash
python3 aes_crack.py <encrypted_file.aes> <wordlist.txt> [output.zip]
```

### Examples

```bash
python3 aes_crack.py backup.aes /usr/share/wordlists/rockyou.txt

python3 aes_crack.py database_backup.zip.aes wordlist.txt decrypted.zip
```

## How It Works

1. Reads passwords from the provided wordlist
2. Attempts to decrypt the .aes file with each password
3. Stops when the correct password is found
4. Extracts the decrypted archive
5. Searches for and parses JSON files (e.g., db.json)
6. Displays potential credentials and sensitive data

## Output

The tool provides:
- Password attempt statistics
- Cracking speed (passwords/second)
- Archive contents listing
- Parsed JSON data
- Extracted credentials and hashes

## Legal Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for ensuring they have permission to decrypt any files they target with this tool.

## License

MIT License
