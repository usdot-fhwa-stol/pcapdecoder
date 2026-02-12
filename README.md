# PCAP Decoder for SAE J2735 Messages

This script decodes SAE J2735 messages from UDP, WSMP, or MQTT packets in PCAP files. The decoded output is saved to a file with the same name as the original PCAP file and a report on the decoding is printed to the terminal.

**Note:** The script currently outputs data as a JSON. Support for XML is possible if requested.

## Prerequisites

- tkinter
- pyshark

Run the [install_dependencies.sh](/install/install_dependencies.sh) script to install all dependencies. 
```bash
cd install
./install_dependencies.sh
```


## Usage

1. Move your PCAP file containing J2735 messages to the [logs](/logs) directory.
2. Execute the script:
```
cd src
./pcapDecode.py
```
3. Follow the on-screen prompts.
4. Chosen file contents will be decoded, printed to the terminal, and written to a log of the same name in the [decoded](/decoded) directory.

### Version

Version 2.1 – Oct 02, 2025
