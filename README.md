# SafeScan
SafeScan is a Smart File Behaviour Analyzer designed to detect potentially malicious or suspicious files by analyzing file entropy, extensions, and presence of known suspicious strings. It helps users monitor folders for new files, analyze them heuristically, quarantine flagged files, and generate detailed reports in text and PDF formats.

---

## Features

- Monitors a specified folder for new files in real-time
- Calculates entropy of file contents to detect randomness (potential obfuscation)
- Checks for suspicious strings like "powershell", "cmd.exe", "eval", and "exec"
- Flags files with bad extensions (e.g., `.exe`, `.bat`, `.js`)
- Quarantines flagged files to a dedicated folder
- Generates exportable reports in both text and PDF formats
- Multi-threaded monitoring and processing for efficient scanning

---

## Installation

Requires Python 3.7+ and the following packages:

might require some module installation just 
pip install <module name>

for example:
pip install reportlab
pip install python-magic

---

## Usage

Clone the repository:
git clone <repo-url>
cd S2S1CW1
python gui.py

