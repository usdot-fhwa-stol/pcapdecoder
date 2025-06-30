# PCAP Decoder for SAE J2735 Messages

This script decodes PCAP files containing SAE J2735 messages. The decoded output is displayed in the terminal and saved to a file with the same name as the original PCAP file.

**Note:** The script currently outputs data as a JSON. Support for XML will be added soon.

## Supported Platforms
- **Linux** (Primary)
- **Windows and macOS** (Adaptation possible)

## Prerequisites

- Python 3
- tkinter
- pyshark

To install the necessary dependencies, run:
```
sudo ./install_dependencies.sh
```

## Usage

1. Move your PCAP file containing J2735 messages to the `logs` directory.
2. Execute the script:
```
cd src
./pcapDecode.py
```
3. Follow the on-screen prompts.
4. Chosen file contents will be decoded, printed to the terminal, and written to a log of the same name in the `decoded` directory.

### Version
Version 1.5 – June 30, 2025
