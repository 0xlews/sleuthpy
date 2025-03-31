```
 __ _            _   _       ___       
/ _\ | ___ _   _| |_| |__   / _ \_   _ 
\ \| |/ _ \ | | | __| '_ \ / /_)/ | | |
_\ \ |  __/ |_| | |_| | | / ___/| |_| |
\__/_|\___|\__,_|\__|_| |_\/     \__, |
                                 |___/ 
```

SleuthPy is a Python utility designed to decode obfuscated content within files. Utilising regex pattern recognition techniques, it scans through a file to identify strings potentially encoded using Base64, Hexadecimal, URL and binary encoding methods. Current support for multiple encoding methods and output file formats, expanding with future development.

## Table of Contents
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Installation](#installation)
- [Usage](#usage)
- [Functionality](#functionality)
- [License](#license)

## Getting Started

### Requirements
- Python 3.10.4 or higher
- Libraries: `tqdm`

### Installation
Clone the repository.

Ensure Python 3 is installed on your system. Install the required libraries using pip:

```bash
pip install tqdm
```

## Usage
Getting started and usage guide:

```bash
python sleuth.py
```

Run SleuthPy using the following command:

```bash
python sleuth.py --input INPUT_FILE --output OUTPUT_FILE [-e ENCODING]
```

- **--input INPUT_FILE**: Specify the path to the file containing the encoded strings.
- **--output OUTPUT_FILE**: Define the path to the file where the decoded data will be written. The output file must have a valid extension (.csv or .json).
- **-e, --encoding ENCODING** (optional): Choose the encoding method to detect ("Base64", "Hexadecimal", "URL Encoding", "Binary"). If this option is omitted, all encoding methods are used.

### Examples

#### Detecting All Encodings
```bash
python sleuth.py --input example.txt --output results.csv
```
This command scans `example.txt` for all supported encoding types and outputs the decoded data in `results.csv`.

#### Specific Encoding Detection
```bash
python sleuth.py --input example.txt --output results.json -e Base64
```
In this example, `sleuth.py` will only look for Base64 encoded strings in `example.txt` and save the decoded results in `results.json`.

## Functionality
- **Detect and Decode Various Encoded Strings**: Identifies and accurately decodes potential Base64, Hexadecimal, URL-encoded, and Binary strings.
- **Selective Decoding**: Allows specifying the encoding method, providing flexibility to focus on specific types of encoded strings.
- **Output Formats**: Supports CSV or JSON for output, catering to different user needs.
- **Efficient Decoding**: Avoids duplicate decoding of strings valid in multiple formats.

## License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
