![Alt text](https://2000ad.com/wp-content/uploads/2021/06/2000AD-wallpaper-02.jpg)

# DREDD - A Malware Analysis Tool
**By**: GRI5H (Neil Moir), BSc (Hons) Ethical Hacking, 3rd Year

Dynamic Rapid Evaluation and Detection Daemon **(DREDD)** is a Python script for static malware analysis, providing file metadata (size, type, entropy, hashes, imports) and VirusTotal lookups for files and URLs. Designed to keep those officers in the field equipped with the right tool to make a JUDGEMENT call. It runs natively or in a Docker container for isolation and portability. 
<br><br>
I would recommend running it natively as I'm still troubleshooting some Docker stuff, ~~the option is there to show that I attempted~~. It works, it builds, but it requires some verbose input to function and I think this hinders the flow of usage. <br><br>I will likely work on some kind of wrapper script to run this properly once I get some time, in the meantime the external dependencies needed to run DREDD are very minimal.
<br><br>
## Features
- **Analyse files**: Extract metadata, hashes, and strings, with optional VirusTotal hash lookup.
- **Scan URLs**: Someone send you a dodgy link? Query VirusTotal for URL analysis.
- **Extracts strings**: Extract ASCII strings from a given file
- **Static files**: Outputs results to console cleanly, and files (`<file>_strings.txt`, `Hash_Results_JSON/<hash>_JSON.txt`).
- **Offline mode**: Offline mode for file analysis without VirusTotal.

![URL demo](https://github.com/user-attachments/assets/5c7852ce-f5e5-4eb9-ab6f-35a6760375a7)

## Prerequisites
- **Python 3.9+** (for native usage).
- **Docker** (for containerized usage, runs Python 3.13).
- **VirusTotal API Key**: Required for online analysis (free from [VirusTotal](https://www.virustotal.com/gui/join-us)).

## Installation

### Native Usage
1. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip
   pip3 install -r requirements.txt
   ```
   requirements.txt contains the following dependencies:
   
     ```bash
   requests>=2.28.0
   lief>=0.12.0
   tabulate>=0.8.10
      ```
2. **Set API Key** (choose one):
   - Hardcoded:
   Edit DREDD.py and replace os.getenv("VT_API_KEY") in the HEADERS section with your API key, then you're good to go:

      ```python
      HEADERS = {
       "accept": "application/json",
       "x-apikey": "your_api_key_here",
       "user-agent": "DREDD/1.0"
      }
      ```
   - Environment Variable:<br>
     Linux:
     ```bash
        export VT_API_KEY=your_api_key
     ```
     Powershell:
     ```powershell
      $env:VT_API_KEY = "your_api_key"
      ```
### Docker Usage

1. **Install Docker**

2. **Build Docker Image**:<br>
   Navigate to the file directory, then build ->
   ```bash
   cd path/to/DREDD/directory
   
   docker build -t dredd .
   ```
3. **Set API Key**:
   ```bash
   echo "VT_API_KEY=your_api_key_here" > .env
   chmod 600 .env
   ```
## Usage

### Native CLI

Running directly with Python:
   ```bash
   python3 DREDD.py [flags]
   ```
#### Flags
-u or --url <url>: Scan a URL via VirusTotal (e.g., https://google.com).
   ```bash
   python3 DREDD.py --url https://google.com
   ```
-f or --file <file>: Analyse a file (metadata, hashes, VirusTotal, string extraction)
   ```bash
   python3 DREDD.py --file <file_path>
   ```
--offline: Used with --file to avoid VirusTotal analysis
   ```bash
   python3 DREDD.py --file <file_path> --offline
   ```
-h or --help: Shows help output

   ```bash
   python3 DREDD.py --help
   ```
### Docker CLI
Flags explained above, for conciseness just flags and usage here.

-u or --url:
   ```bash
   docker run --rm --env-file .env dredd --url https://google.com
   ```
-f or --file:
   ```bash
   docker run --rm --env-file .env -v /path/to/sample.exe:/app/sample.exe -v /path/to/output:/app dredd --file sample.exe
   ```
--offline
   ```bash
   docker run --rm --env-file .env -v /path/to/sample.exe:/app/sample.exe -v /path/to/output:/app dredd --file sample.exe --offline
   ```
## Notes

- VirusTotal free API has a rate limit in place:
   - 500/day or 4/minute
- If hard-coding the API, don't forget to delete if you decide to share the script
- Work in progress, open to advice


**Thanks to the awesome art creators for the Judge Dredd image, the original file can be found here - https://2000ad.com/wp-content/uploads/2021/06/2000AD-wallpaper-02.jpg**
