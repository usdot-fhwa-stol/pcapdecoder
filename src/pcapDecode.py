#!/usr/bin/env python3
import j2735_202409
import os, sys
import decoder_helper
from collections import defaultdict
from binascii import unhexlify
import contextlib
import io
from enum import Enum

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

    # Browse for the PCAP file
    file = decoder_helper.browse_file()
    if not file:
        raise ValueError("No file selected. Exiting.")

    # Make sure the decoded directory exists alongside src
    srcDir     = os.path.dirname(os.path.abspath(__file__))
    decodedDir = os.path.abspath(os.path.join(srcDir, '..', 'decoded'))
    os.makedirs(decodedDir, exist_ok=True)

    # Build the output path
    decodedFile = decoder_helper.formatFileName(file)
    decodedPath     = os.path.join(decodedDir, decodedFile)
    w = open(decodedPath, 'w')

    # Extract packets from the PCAP file
    packets = decoder_helper.extract_packets(file)
    if not packets:
        raise ValueError("No UDP packets found in the selected file. Exiting.")

    # Iterate per timestamp preserving chronological order
    for timestamp in sorted(packets.keys()):
        payload_list = packets[timestamp]
        for line in payload_list:
            lower_line = line.lower()
            half_limit = len(lower_line) // 2
            for msg_id in msgIds:
                pos = 0
                search_limit = half_limit
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

    # Write the decoded message IDs and their counts to the output file
    decoder_helper.writeIds(w, msgId_count)
    
    # Calculate and write IPG statistics
    decoder_helper.writeIpgStats(w, msgId_timestamps)
    w.close()

    print('\nDecoding Complete. Check', decodedFile, '\n')
    sys.exit(0)

if __name__=="__main__":
    main()
