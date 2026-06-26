#!/usr/bin/env python3
import j2735_202409
import os, sys
import decoder_helper
from collections import defaultdict
from binascii import unhexlify
import contextlib
import io
from enum import Enum

import argparse
from pathlib import Path

class MsgID(Enum):
    MAP  = "0012"
    SPAT = "0013"
    BSM  = "0014"
    SRM  = "001d"
    SSM  = "001e"
    TIM  = "001f"
    PSM  = "0020"
    SDSM = "0029"

def main():
    # Initialize the message frame and ID tracking
    frame = j2735_202409.MessageFrame.MessageFrame
    msgIds = list(MsgID)  # All message ID types from Enum
    msgId_count = defaultdict(int)  # dictionary to track decoded msgId and their counts
    msgId_timestamps = defaultdict(list)  # track timestamps for IPG calculation

    # Setup argument parser
    parser = argparse.ArgumentParser(description="PCAP Decoder")
    parser.add_argument("--input-file", help="Path to the PCAP file")
    parser.add_argument("--output-dir",help="Directory for the output log file")
    args = parser.parse_args()

    # File path can be given by a command line argument or chosen with a UI
    if args.input_file:
        # Batch mode: use the hardcoded path from the argument
        file = args.input_file
        print(f"Batch mode: Decoding {file}")
    else:
        # Manual mode: trigger the UI
        file = decoder_helper.browse_file()

    if not file:
        raise ValueError("No file selected. Exiting.")
    
    # Output file path can be chosen by a command line argument. Otherwise it is stored in a default location. 
    if args.output_dir:
        # Use provided directory, but keep the specific naming pattern
        decoded_dir = Path(args.output_dir)
        os.makedirs(decoded_dir, exist_ok=True)
        decodedFile = decoder_helper.formatFileName(file)
        decoded_path = decoded_dir / decodedFile
        print(f"Outputting to: {decoded_path}")
    else:
        # Make sure the decoded directory exists alongside src
        srcDir     = os.path.dirname(os.path.abspath(__file__))
        decoded_dir = os.path.abspath(os.path.join(srcDir, '..', 'decoded'))
        os.makedirs(decoded_dir, exist_ok=True)

        # Build the output path
        decodedFile = decoder_helper.formatFileName(file)
        decoded_path     = os.path.join(decoded_dir, decodedFile)
        
    w = open(decoded_path, 'w')

    # Extract packets from the PCAP file
    packets = decoder_helper.extract_packets(file)
    if not packets:
        raise ValueError("No UDP packets found in the selected file. Exiting.")

    # Iterate per timestamp preserving chronological order
    for timestamp in sorted(packets.keys()):
        payload_list = packets[timestamp]
        for line in payload_list:
            lower_line = line.lower()
            search_limit = (len(lower_line) * 2) // 3  # Limit search to first 2/3 of the payload
            for msg_id in msgIds:
                pos = 0
                while pos <= search_limit:
                    idx = lower_line.find(msg_id.value, pos, search_limit + 1)
                    if idx == -1:
                        break
                    buf = lower_line[idx:].strip('\n')
                    try:
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            frame.from_uper(unhexlify(buf))
                    except Exception:
                        # Advance past this occurrence to look for another instance.
                        pos = idx + len(msg_id.value)
                        continue
                    # Successful decode; record and stop scanning this msg_id for current line.
                    decoder_helper.decode(buf, frame, w, msgId_count, msg_id.value, timestamp, msgId_timestamps)
                    break

    # Write the decoded message IDs and their counts to terminal
    decoder_helper.writeIds(sys.stdout, msgId_count)
    
    # # Calculate and write IPG statistics to terminal
    decoder_helper.writeIpgStats(sys.stdout, msgId_timestamps)
    w.close()

    print('\nDecoding Complete. Check', decodedFile, '\n')
    sys.exit(0)

if __name__=="__main__":
    main()
