#!/usr/bin/env python3
import j2735_202409
import os, sys
import decoder_helper
from collections import defaultdict

def main():
    # Initialize the message frame and ID tracking
    frame = j2735_202409.MessageFrame.MessageFrame
    msgIds = ['0012','0013','0014','001f','0020','0029'] # can be updated to include other PSIDs
    msgId_count = defaultdict(int)  # dictionary to track decoded msgId and their counts

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

    # Process each packet
    for line in packets:
        for id in msgIds:
            idx = line.find(id)
            if (idx != -1):
                data = line[idx:]
                if decoder_helper.isValidMsgSize(data):
                    if not decoder_helper.isBSMPSID(data):
                        decoder_helper.decode(data, frame, w, msgId_count, id)

    # Write the decoded message IDs and their counts to the output file
    decoder_helper.writeIds(w, msgId_count)
    w.close()

    print('\nDecoding Complete. Check', decodedFile, '\n')
    sys.exit(0)

if __name__=="__main__":
    main()
