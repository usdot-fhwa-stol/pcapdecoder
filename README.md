# PCAP Decoder for SAE J2735 Messages

This script decodes SAE J2735 messages from UDP, WSMP, or MQTT packets in PCAP files. The decoded output is saved to a file with the same name as the original PCAP file and a decoding report is printed to the terminal.

**Note:** The script currently outputs data as a JSON. Support for XML is possible if requested.

## Prerequisites

- python >=3.8
- tkinter
- pyshark

Run the [install_dependencies.sh](/install/install_dependencies.sh) script to install all dependencies.
```bash
cd install
./install_dependencies.sh
```


## Usage

### Interactive
1. Move your PCAP file containing J2735 messages to the [logs](/logs) directory.
2. Execute the script:
```
cd src
./pcapDecode.py
```
3. Follow the on-screen prompts.
4. Chosen file contents will be decoded, printed to the terminal, and written to a log of the same name in the [decoded](/decoded) directory.

### Non Interactive
1. Move your PCAP file containing J2735 messages to the [logs](/logs) directory or one of your choosing.
2. Execute the script:
```
cd src
./pcapDecode.py [-h] [--input-file INPUT_FILE] [--output-dir OUTPUT_DIR]
```
3. Chosen file contents will be decoded, printed to the terminal, and written to a log of the same name in the [decoded](/decoded) directory.

### Version

Version 2.1 – Oct 02, 2025

## Security & Direction Classifier (check_pcap_security_direction_type.py)

This script scans classic PCAP captures for SAE J2735 V2X messages (MAP, SPaT,
BSM, SDSM, PSM, TIM, SRM, SSM, and CARMA's mobility messages) and reports, per
message, whether it was carried in an IEEE 1609.2 `signedData` or
`unsecuredData` envelope, along with its traffic direction (incoming/outgoing)
and source/destination. It prints a summary table to the terminal — it does
not decode message field contents or write an output file.

It supports plain UDP (Ethernet and Linux cooked captures), MQTT-over-TCP
(Ettifos-vendor OBUs; requires `tshark` for TCP reassembly), and Commsignia's
"Tx Request" ASCII protocol.

### Classifier Usage

```bash
cd src
./check_pcap_security_direction_type.py file1.pcap [file2.pcap ...]
```

### Pros vs. pcapDecode.py

- No dependency on the `j2735_202409` UPER decoder or `pyshark` — runs with
  the standard library alone (tshark is only needed for the optional MQTT
  path).
- Reports packet direction (incoming/outgoing/multicast/etc.) and the
  IEEE 1609.2 security envelope, which pcapDecode.py does not.
- Understands the Commsignia Tx Request protocol and MQTT topic-based
  direction, in addition to raw UDP.
- Accepts multiple PCAP files in one invocation.

### Limitations vs. pcapDecode.py

- Does not decode or print message field contents — pcapDecode.py fully
  decodes each message via UPER decoding and writes a JSON log.
- Detects `signedData` by locating a byte-pattern marker, and does not
  cryptographically validate the signature.
- No interactive file browser or JSON output file; results only go to
  stdout.

Example output:
```bash
### rmnet_data1.pcap results:
Detailed results:
Direction            Message  Security       Source                       Destination                     Count
----------------------------------------------------------------------------------------------------------------------
unknown              SDSM     signedData     192.168.88.40:33846          192.168.88.10:5398                170

Totals by message type:
Message      Signed    Unsecured        Raw      Total
-------------------------------------------------------
SDSM            170            0          0        170

Totals by direction:
  unknown:
    SDSM     signedData     170

#### OBU's eth0.pcap results:
Total packets: 940
UDP packets: 940
MQTT PUBLISH messages: 0
Recognized J2735 packets: 940

Detailed results:
Direction            Message  Security       Source                       Destination                     Count
----------------------------------------------------------------------------------------------------------------------
incoming             SDSM     signedData     80f8:f80:f80f:80f8::27:6bff:9000 80f8:f80:f80f:80f8:5502:171e:a280:b708:9000      940

Totals by message type:
Message      Signed    Unsecured        Raw      Total
-------------------------------------------------------
SDSM            940            0          0        940

Totals by direction:
  incoming:
    SDSM     signedData     940
```
