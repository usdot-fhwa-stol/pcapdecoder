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
    # DSRCmsgID values, as the leading two bytes (UPER) of the MessageFrame.
    # Comment out an entry to exclude that message type from the decoded output.
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
    msg_ids = {m.value: m for m in MsgID}  # DSRCmsgID hex -> MsgID member
    msg_id_count = defaultdict(int)  # dictionary to track decoded msgId and their counts
    msg_id_timestamps = defaultdict(list)  # track timestamps for IPG calculation

    # Browse for the PCAP file
    file = decoder_helper.browse_file()
    if not file:
        raise ValueError("No file selected. Exiting.")

    # Make sure the decoded directory exists alongside src
    src_dir     = os.path.dirname(os.path.abspath(__file__))
    decoded_dir = os.path.abspath(os.path.join(src_dir, '..', 'decoded'))
    os.makedirs(decoded_dir, exist_ok=True)

    # Build the output path
    decoded_file = decoder_helper.format_file_name(file)
    decoded_path     = os.path.join(decoded_dir, decoded_file)
    w = open(decoded_path, 'w')

    # Extract packets from the PCAP file
    packets = decoder_helper.extract_packets(file)
    if not packets:
        raise ValueError("No UDP packets found in the selected file. Exiting.")

    # Iterate per timestamp preserving chronological order
    for timestamp in sorted(packets.keys()):
        for wsm_hex in packets[timestamp]:
            # The DSRCmsgID is the leading INTEGER of the MessageFrame; its UPER
            # encoding is the first two bytes of the WSM. Skip message types not
            # listed in MsgID (e.g. non-J2735 payloads under other PSIDs).
            msg_id = msg_ids.get(wsm_hex[:4].lower())
            if msg_id is None:
                continue
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    frame.from_uper(unhexlify(wsm_hex))
            except Exception:
                continue  # Not a decodable MessageFrame; skip.
            decoder_helper.decode(wsm_hex, frame, w, msg_id_count, msg_id, timestamp, msg_id_timestamps)

    # Write the decoded message IDs and their counts to terminal
    decoder_helper.write_ids(sys.stdout, msg_id_count)
    
    # # Calculate and write IPG statistics to terminal
    decoder_helper.writeIpgStats(sys.stdout, msg_id_timestamps)
    w.close()

    print('\nDecoding Complete. Check', decoded_file, '\n')
    sys.exit(0)

if __name__=="__main__":
    main()
