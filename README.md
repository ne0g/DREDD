# DREDD - Malware Analysis Tool

Dynamic Rapid Evaluation and Detection Daemon **(DREDD)** is a Python script for static malware analysis, providing file metadata (size, type, entropy, hashes, imports) and VirusTotal lookups for files and URLs. It runs natively or in a Docker container for isolation and portability. Although, I would recommend running it natively as I'm still troubleshooting some Docker stuff, the option is there to show that I attempted, but very much still a Docker n00b lol.

**Author**: GRI5H (Neil Moir), BSc (Hons) Ethical Hacking, 3rd Year

## Features
- Analyse files: Extracts metadata, hashes, and strings, with optional VirusTotal hash lookup.
- Scan URLs: Queries VirusTotal for URL analysis.
- Outputs results to console and files (`<file>_strings.txt`, `Hash_Results_JSON/<hash>_JSON.txt`).
- Supports offline mode for file analysis without VirusTotal.

## Prerequisites
- **Python 3.9+** (for native usage).
- **Docker** (for containerized usage).
- **VirusTotal API Key**: Required for online analysis (free from [VirusTotal](https://www.virustotal.com/gui/join-us)).

## Installation

### Native Usage
1. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip
   pip3 install -r requirements.txt
   ```
