import argparse
import hashlib
import os
import time
import math
import re
from collections import Counter
from pprint import pformat
from datetime import datetime
#------------------------------------------------------------------------------------------------------------#
#                       Separated so I can see what's standard and what's not.                               #
#------------------------------------------------------------------------------------------------------------#
import requests # Non-standard library 
import lief  # Non-standard library
from tabulate import tabulate  # Non-standard library

"""
Github: https://github.com/ne0g/DREDD

Dynamic Rapid Evaluation and Detection Daemon (DREDD) - A Static Analysis Script.

A script that assists an analyst in making a "JUDGEMENT CALL" on a file or URL.
The script hashes files, queries VirusTotal on a given URL or hash, analyses file properties such as DOS headers, architecture type, entropy, and string extraction.
Not a replacement for full analysis, but a good starting point for an analyst to make a decision to go further.

Note: Is the banner necessary? No but its 1337 and Judge Dredd was the initial inspiration. 
Feel free to remove it if you want, just remember to remove it from main() too.
"""

HEADERS = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY"),  # Set your API key as an environment variable for security, or hard-code it if you want.
    "user-agent": "DREDD/1.0"
}

BANNER = r"""
 /$$$$$$$  /$$$$$$$  /$$$$$$$$ /$$$$$$$  /$$$$$$$ 
| $$__  $$| $$__  $$| $$_____/| $$__  $$| $$__  $$
| $$  \ $$| $$  \ $$| $$      | $$  \ $$| $$  \ $$
| $$  | $$| $$$$$$$/| $$$$$   | $$  | $$| $$  | $$
| $$  | $$| $$__  $$| $$__/   | $$  | $$| $$  | $$
| $$  | $$| $$  \ $$| $$      | $$  | $$| $$  | $$ 
| $$$$$$$/| $$  | $$| $$$$$$$$| $$$$$$$/| $$$$$$$/
|_______/ |__/  |__/|________/|_______/ |_______/

by GRI5H // Neil Moir // BSc (Hons) Ethical Hacking // 3rd Year

|_|0|_|
|_|_|0|
|0|0|0|
"""
def scan_url(url_to_scan):
    """
    Scan a URL using VirusTotal API, retrieve an ID that gets fed to the analysis URL API, 
    the vendor results are then returned back.

    The user supplies the URL in main() via the --url flag.
    """

    print(f"\nScanning URL: {url_to_scan}")
    print("-" * 50)

    # URL for submitting URLs to VirusTotal, all caps indicate its CONSTANT so shouldn't change.
    VT_URL = "https://www.virustotal.com/api/v3/urls"
    
    payload = {"url": url_to_scan}
    response = requests.post(VT_URL, headers=HEADERS, data=payload)

    # If the response is successful, return the analysis ID, otherwise let the user know it failed and return None.
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        print("URL submitted successfully.")
    else:
        print(f"Error submitting URL: {response.status_code} - {response.text}")
        return None


    # Define variables for the number of attempts and delay between attempts at the API call. Stops script hammering API when API is busy.
    max_attempts = 10
    delay_seconds = 5
    
    # This is the analysis API URL, it takes the analysis ID from the previous step and returns vendor results.
    ANALYSIS_URL = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    # Loop that checks the status code of the request to the analysis URL, request is queued so it needs time to return.
    for attempt in range(max_attempts):
        try:
            analysis_response = requests.get(ANALYSIS_URL, headers=HEADERS)
            
            if analysis_response.status_code == 200:
                result = analysis_response.json()
                status = result["data"]["attributes"]["status"]
                
                if status == "completed":
                    stats = result["data"]["attributes"]["stats"]
                    
                    # A table of data that can be used by the tabulate library to display results in a nice format.
                    vendor_data = [
                        ["Malicious", stats['malicious']],
                        ["Suspicious", stats['suspicious']],
                        ["Harmless", stats['harmless']],
                        ["Undetected", stats['undetected']]
                    ]

                    print(f"\nURL Analysis Results For: {url_to_scan}\n")
                    print(tabulate(vendor_data, headers=["Category", "Count"], tablefmt="rst"))
                    
                    return None
                
                else:
                    print(f"Analysis not complete yet (Status: {status}). Waiting {delay_seconds} more seconds...")
                    if attempt < max_attempts - 1:
                        time.sleep(delay_seconds)
            else:
                print(f"Error retrieving URL analysis: {analysis_response.status_code} - {analysis_response.text}")
                return None
        
        except Exception as e:
            print(f"Error retrieving URL analysis: {e}")
            return None
        
    print("Analysis did not complete in time. Try again later.")
    return None

def hash_generator(file_path):
    """
    Generate MD5 and SHA256 hashes for the provided file.
    Reads the file in 256kb chunks to handle large files efficiently, combats bottlenecking.
    """
    
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    # 256KB per chunk size to handle large files efficiently.
    chunk_size = 256000

    try:
        # Opens the file in binary mode and reads it in chunks.
        with open(file_path, "rb") as file:
            while True:
                file_chunk = file.read(chunk_size)
                if not file_chunk:
                    break
                
                # Update the hash objects with the chunk of data read from the file until the end of the file.
                md5_hash.update(file_chunk)
                sha256_hash.update(file_chunk)
    
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    
    except PermissionError:
        print(f"Permission denied: {file_path}")
        return None
    
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
    # Returns a dictionary with the file path, MD5 hash, and SHA256 hash.
    return {
        "file": file_path,
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest()
    }

def scan_hash(sha_256):
    """
    Takes the SHA256 hash of the file provided then queries VirusTotal for it.
    You can use other hashes, but SHA256 is recommended.
    """

    print(f"\nScanning hash: {sha_256}")
    print("-" * 50)

    HASH_URL = f"https://www.virustotal.com/api/v3/files/{sha_256}"
    
    try:
        response = requests.get(HASH_URL, headers=HEADERS)

        # Saves the pretty-printed JSON to a file in an output directory
        output_dir = "Hash_Results_JSON"
        output_file = os.path.join(output_dir, f"{sha_256}_JSON.txt")
        
        # Print current working directory for debugging
        print(f"Current working directory: {os.getcwd()}")

        # Create output directory if it doesn't exist
        try:
            os.makedirs(output_dir, exist_ok=True)
        
        except OSError as error:
            print(f"Failed to create directory {output_dir}: {error}")
            return None

        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(pformat(response.json()))
        
        except OSError as e:
            print(f"Failed to write file {output_file}: {e}")
            return None

        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["last_analysis_stats"]

            vendor_data = [
                ["Malicious", stats['malicious']],
                ["Suspicious", stats['suspicious']],
                ["Harmless", stats['harmless']],
                ["Undetected", stats['undetected']]
            ]
            
            print(f"\nHash Analysis Results For: {sha_256}\n")
            print(tabulate(vendor_data, headers=["Category", "Count"], tablefmt="rst"))
            print(f"Results saved to: {output_file}")
        
        elif response.status_code == 404:
            print(f"Hash not found in VirusTotal: {sha_256}")
            return None
    
        else:
            print(f"Error retrieving hash analysis: {response.status_code} - {response.text}")
            return None
    
    except Exception as e:
        print(f"Error retrieving hash analysis: {e}")
        return None

def get_file_metadata(file_path):
    """
    Extract basic file metadata like size, type, and checks if its a binary.
    """
    
    try:
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB

        # Parse the binary using LIEF.
        binary = lief.parse(file_path)
        
        # Check if the file is a PE or ELF binary.
        file_type = "PE" if lief.is_pe(file_path) else "ELF" if lief.is_elf(file_path) else "Unknown, is this a ZIP?"
        
        return file_size, file_type, binary
    
    # If the file doesn't exist, or its not a binary, return None for file size, type, and binary.
    except Exception as e:
        print(f"Error getting file metadata: {e}")
        return None, None, None

def extract_strings(file_path):
    """
    Extract printable ASCII strings from a binary file using regex and save them to a text file.
    Strings are saved to '<file_path>_strings.txt' in the same directory. 
    The file is read in 256KB chunks for efficiency. Returns the path to the output file or None
    if an error occurs.
    """
    output_file = f"{file_path}_strings.txt"
    chunk_size = 256000
    min_string_length = 4

    # Match 4+ printable ASCII characters (letters, numbers, symbols) in binary data.
    pattern = re.compile(b'[ -~]{%d,}' % min_string_length)

    try:
        with open(file_path, "rb") as file, open(output_file, "w", encoding="utf-8") as output:
            output.write(f"Strings extracted from {file_path}:\n")
            output.write(f"Extracted on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            buffer = b""

            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    if buffer:
                        matches = pattern.findall(buffer)
                        for match in matches:
                            output.write(match.decode("ascii", errors="ignore") + "\n")
                    break
                
                # Append the chunk to the buffer and search for matches.
                buffer += chunk
                matches = pattern.findall(buffer)
                
                # Write matches to the output file, ignoring non-ASCII characters.
                for match in matches:
                    output.write(match.decode("ascii", errors="ignore") + "\n")
                last_match_end = pattern.search(buffer)
                
                ## If there are no matches, keep the last part of the buffer for the next iteration.
                if last_match_end:
                    buffer = buffer[last_match_end.end():]
                else:
                    buffer = buffer[-min_string_length:] if len(buffer) > min_string_length else buffer

        return output_file
    
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    
    except PermissionError:
        print(f"Permission denied: {file_path}")
        return None
    
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def analyse_binary(binary, file_type):
    """
    Extract imports, and PE header info from a binary.

    This later gets used to display the results in a tabulate format.
    The function checks if the binary is a PE file, and if so, extracts the imports and PE header info.
    """
    
    # If the file is not a binary, return None for imports, and pe_header_info
    if not binary:
        return None, None

    imports = []
    pe_header_info = {}

    if file_type == "PE" and hasattr(binary, "imports"):
        imports = [imp.name for imp in binary.imports]
    
    imports = imports if imports else ["None detected"]

    if file_type == "PE":
        machine_types = {
            0x14c: "x86",    # Intel x86
            0x8664: "x64",  # AMD64
            0x1c0: "ARM (32-bit)",
            0xaa64: "ARM64 (64-bit)"
        }

        machine_value = binary.header.machine.value
        
        machine_str = machine_types.get(machine_value, f"Unknown ({hex(machine_value)})")
        
        flags = []

        characteristics_value = binary.header.characteristics
        
        if characteristics_value & 0x0002:
            flags.append("Executable")
        
        if characteristics_value & 0x0020:
            flags.append("DLL")
        
        characteristics_str = ", ".join(flags) if flags else "None"
        
        pe_header_info = {
            "dos_magic": "MZ (4D 5A)" if binary.dos_header.magic == 0x5a4d else hex(binary.dos_header.magic),
            "pe_magic": hex(binary.optional_header.magic.value) if hasattr(binary, "optional_header") else "N/A",
            "machine": machine_str,
            "characteristics": characteristics_str,
        }

    return imports, pe_header_info

def calculate_entropy(file_path):
    """
    Calculate the Shannon entropy of a file to measure its randomness, aiding malware analysis.
    Reads the file in 128KiB chunks to count byte occurrences, then applies the Shannon entropy formula.
    High entropy (near 8) suggests encrypted or compressed data; low entropy (near 0) indicates uniformity.
    Returns the entropy value (float, 0 to 8) or None if an error occurs.
    """
    
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
            # Check if the file is empty, if it is, return 0.0 entropy.
            if len(data) == 0:
                print("File is empty.")
                return 0.0
            
            # Count the occurrences of each byte value in the file.
            byte_counts = Counter(data)
            
            # Calculate the entropy using the Shannon entropy formula
            entropy = -sum((count / len(data)) * math.log2(count / len(data)) 
                          for count in byte_counts.values())
            
            return entropy
    
    except Exception as e:
        print(f"Error calculating entropy: {e}")
        return None

def analyse_file(file_path, offline=False):

    print(f"\nAnalysing file: {file_path}\n")

    hashes = hash_generator(file_path)
    if not hashes:
        return None

    # Only scans the hash with VirusTotal if not in offline mode, which it is by default.
    hash_result = None
    if not offline:
        hash_result = scan_hash(hashes['sha256'])

    file_size, file_type, binary = get_file_metadata(file_path)
    if file_size is None:
        return None

    entropy = calculate_entropy(file_path)
    if entropy is None:
        return None

    imports, pe_header_info = analyse_binary(binary, file_type)
    if imports is None:
        return None
    
    strings_file = extract_strings(file_path)
    if strings_file:
        print(f"Strings extracted to: {strings_file}")
    else:
        print("No strings extracted.")
    
    table_data = [
        ["File Size", f"{file_size:.2f} MB"],
        ["File Type", file_type],
        ["Entropy", f"{entropy:.2f}"],
        ["MD5", hashes['md5']],
        ["SHA256", hashes['sha256']],
        ["Imports", f"{', '.join(imports[:5])}{'...More' if len(imports) > 5 else ''}"]
    ]

    """
    If the file IS a PE file, then it extends the table with the PE header info, otherwise you just get the table_data data.
    This could be expanded in the future to include more file types, but for now it's just PE.
    """
    if pe_header_info:
        table_data.extend([
            ["DOS Magic", pe_header_info['dos_magic']],
            ["PE Magic", pe_header_info['pe_magic']],
            ["Machine Type", pe_header_info['machine']],
            ["Characteristics", pe_header_info['characteristics']]
        ])

    print(tabulate(table_data, headers=["ATTRIBUTE", "RESULT"], tablefmt="rst"))

def parse_args():

    parser = argparse.ArgumentParser(
        description="DREDD: A Static Analysis Tool. Cleaning up Mega-City One, one file at a time.",
        epilog="Example: python DREDD.py --file {file_path_here} --url {url_here} --offline"
    )

    # Adds arguements to the parser, these are the command line args that users can use to run the script.
    parser.add_argument("-f", "--file", help="Path to the file to hash and analyze")
    parser.add_argument("-u", "--url", help="Scan a URL using VirusTotal")
    parser.add_argument("--offline", action="store_true", help="Run in offline mode (skips VirusTotal API calls for files)")

    args = parser.parse_args()

    # If the user doesn't supply an arg, it'll print the help message and exit the program.
    if not args.file and not args.url:
        parser.print_help()
        print("\nError: At least one of --file or --url must be provided. Use --offline for no VirusTotal API calls.")
        return None
    
    # Returns the args object to main() with the supplied args.
    return args

def main():
    print(BANNER)

    args = parse_args()
    
    if args is None:
        return None

    if args.file:
        analyse_file(args.file, offline=args.offline)
    
    if args.url:
        if args.offline:
            print("\nWarning: URL scanning requires VirusTotal API and is skipped in offline mode. Only use with --url.")
        else:
            scan_url(args.url)
    
    print("\nAnalysis complete, officer. Do you need to escalate?\n")

if __name__ == "__main__":
    main()