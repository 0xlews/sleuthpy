
"""
 __ _            _   _       ___       
/ _\ | ___ _   _| |_| |__   / _ \_   _ 
\ \| |/ _ \ | | | __| '_ \ / /_)/ | | |
_\ \ |  __/ |_| | |_| | | / ___/| |_| |
\__/_|\___|\__,_|\__|_| |_\/     \__, |
                                 |___/ 
"""

import argparse
import base64
import binascii
import csv
import os
import re
import sys
import urllib.parse
import json
from tqdm import tqdm

# Ensure Python version compatibility
if sys.version_info < (3, 10, 4):
    sys.exit("Requires Python 3.10.4 or higher")

# Valid base64 check
def is_valid_base64(s):
    pattern = re.compile(r'^(?:%[0-9a-fA-F]{2}|[A-Za-z0-9_.~!$&\'()*+,;=:@/-])+$')
    return bool(pattern.match(s))

# Valid hexadecimal check
def is_valid_hex(s):
    pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(pattern.match(s))

# Valid encoded URL check
def is_valid_url(s):
    pattern = re.compile(r'(?:%[0-9a-fA-F]{2}|[A-Za-z0-9_.~!$&\'()*+,;=:@/-])+')
    return bool(pattern.match(s))

# Valid binary check
def is_valid_binary(s):
    return all(c in '01' for c in s) and len(s) % 8 == 0

def decode_hex(s):
    try:
        return bytes.fromhex(s).decode('utf-8')
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None

def decode_binary(binary_str):
    try:
        # Ensure the binary string is continuous without spaces
        binary_str = binary_str.replace(" ", "")

        # Decode each 8-bit segment
        text = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
        
        if is_readable_text(text):
            return text
        else:
            return "Invalid binary string"
    except Exception as e:
        return f"Error: {e}"

# Function to determine if a string is mostly readable text
def is_readable_text(s):
    threshold = 0.95
    total_chars = len(s)
    printable_chars = sum(1 for c in s if c.isprintable())
    ratio = printable_chars / total_chars
    return ratio > threshold

# Function to detect and decode encoded strings in a file
def detect_and_decode(file_path, encoding=None):
    with open(file_path, 'rb') as f:
        content = f.read().decode('utf-8', 'ignore')  # decode to handle binary

    # Change from byte literals to string literals
    pattern_b64 = r'(?<!\w)(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?!\w)'
    pattern_hex = r'\b[0-9a-fA-F]{2,}\b'
    pattern_url = r'https?%3A%2F%2F[\w%.-]+(?:%2F[\w%.-]*)*'
    pattern_binary = r'\b[01]{8,}\b'

    # Find encoded strings matching the regular expressions
    encoded_strings_b64 = re.findall(pattern_b64, content)
    encoded_strings_hex = re.findall(pattern_hex, content)
    encoded_strings_url = re.findall(pattern_url, content)
    encoded_strings_binary = re.findall(pattern_binary, content)  # No need to encode

    decoded_data = []

    if encoding in [None, "Base64"]:
        for encoded in tqdm(encoded_strings_b64, desc="Decoding Base64"):
            if is_valid_base64(encoded):
                try:
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    if decoded.strip() and is_readable_text(decoded):
                        decoded_data.append((encoded, "Base64", decoded))
                except:
                    pass

    MIN_HEX_LENGTH = 4

    if encoding in [None, "Hexadecimal"]:
        for encoded in tqdm(encoded_strings_hex, desc="Decoding Hex"):
            if is_valid_hex(encoded) and len(encoded) >= MIN_HEX_LENGTH:
                decoded = decode_hex(encoded)
                if decoded and decoded.strip() and is_readable_text(decoded):
                    decoded_data.append((encoded, "Hex", decoded))

    if encoding in [None, "URL Encoding"]:
        for encoded in tqdm(encoded_strings_url, desc="Decoding URL"):
            if is_valid_url(encoded):
                try:
                    decoded = urllib.parse.unquote(encoded)
                    if decoded.strip() and is_readable_text(decoded):
                        decoded_data.append((encoded, "URL Encoding", decoded))
                except:
                    pass

    if encoding in [None, "Binary"]:
        for encoded in tqdm(encoded_strings_binary, desc="Decoding Binary"):
            if is_valid_binary(encoded):
                decoded = decode_binary(encoded)
                if decoded.strip() and is_readable_text(decoded):
                    decoded_data.append((encoded, "Binary", decoded))

    return decoded_data

# Main function to handle command-line arguments and execute the program
def main():
    parser = argparse.ArgumentParser(description="Decode encoded strings in a file")
    parser.add_argument("-i", "--input", help="Input file path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "-e", "--encoding",
        choices=["Base64", "Hex", "URL Encoding"],
        help="Specify the encoding method to detect (default: all)"
    )

    args = parser.parse_args()

    # Check if no arguments were provided
    if len(sys.argv) == 1:
        print(__doc__)  # Print ASCII art
        parser.print_help()  # Print help message
        sys.exit(1)  # Exit the script

    # Check the output file extension
    output_file_path, ext = os.path.splitext(args.output)
    if not ext or ext.lower() not in ['.csv', '.json']:
        sys.exit("Output file must have a valid extension (.csv or .json)")

    decoded_data = detect_and_decode(args.input, args.encoding)

    if ext.lower() == '.csv':
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Encoded String", "Encoding Type", "Decoded String"])
            writer.writerows(decoded_data)

    elif ext.lower() == '.json':
        json_data = [
            {"Encoded String": enc, "Encoding Type": enc_type, "Decoded String": dec}
            for enc, enc_type, dec in decoded_data
        ]
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":
    main()
