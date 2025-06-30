#!/usr/bin/env python3

import J2735_201603_2023_06_22
import os, sys, json, pyshark
from binascii import unhexlify
from collections import defaultdict
from tkinter import Tk, filedialog

def browse_file():
    """Open file dialog and return the selected file path"""
    root = Tk()
    root.withdraw()
    srcDir = os.path.dirname(os.path.abspath(__file__))
    logDir = os.path.join(srcDir, '../logs')
    filename = filedialog.askopenfilename(initialdir=logDir,
                                          title = "Select a File",
                                          filetypes=[("PCAP Files", "*.pcap")])
    return filename

def formatFileName(file):
    file = os.path.basename(file)
    fileName = 'decoded_' + file.replace('.pcap', '.txt')
    return fileName

def extract_packets(pcap_file):
    """Extract packets from the PCAP file and return a list of packet data."""
    capture = pyshark.FileCapture(pcap_file, display_filter='udp')
    packets = []
    
    for packet in capture:
        try:
            packets.append(packet.data.data)
        except AttributeError:
            continue
    
    return packets

def writeIds(w, msgId_count):
    w.write('\nDecoded Message ID Counts:\n')
    print('\nDecoded Message ID Counts:')
    for msgId, count in msgId_count.items():
        w.write(f'{msgId}: {count}\n')
        print(f'{msgId}: {count}')

def isValidMsgSize(line):
    tempFrame = line[6:]
    if (len(tempFrame) > 510):
        frameSize = 8
        encodedSize = int(line[5:8], 16) * 2
    else: 
        frameSize = 6
        encodedSize = int(line[4:6], 16) * 2

    newFrame = line[frameSize:]
    if (encodedSize == len(newFrame)):
        print("Valid message.")
        return True
    elif (encodedSize < len(newFrame) + 150):
        print("Checking for certificate or digest hash.")
        # If the message is larger than expected, it may contain a certificate or digest hash
        if isSigned(newFrame):
            print("Message is signed, continuing.")
            return True
    else:
        print("Not a valid message, continuing.")
        return False

def isSigned(frame):
    """Checks if the message is signed by looking for a certificate or digest hash.
    Returns:
        bool: Validity of signed message.
    """
    # Find all possible cert or digest hashes, by length
    length = len(frame)
    possibleCert = frame[frame.find("00030180"):]
    possibleDigest = frame[length-(76*2)+2:]

    # Extract all verified cert or digest hashes
    if (possibleCert[0:8] == "00030180"):
        fullCert = possibleCert[8:24]
        if fullCert:
            print("Found certificate hash: ", fullCert)
            return True

    if ((possibleDigest[0:2] == possibleDigest[18:20]) and possibleDigest[18:20] == "80"):
        hashId = possibleDigest[2:18]
        if hashId:
            print("Found digest hash: ", hashId)
            return True

    return False

def isBSMPSID(line):
    """Check to ensure a found BSM PSID (0x0020) is not actually PSM DSRCmsgID 32 (0x0020). This is done by looking for the Element ID (0x0380),
    followed by the BSM DSRCmsgID 20 (0x0014). Specifically, looking for 0020...0380...0014, else false.

    Args:
        line (str): Full message under test.
    Returns:
        bool: Validity of BSM PSID.
    """
    element_id = '0380'
    bsm_id = '0014'

    idx1 = line.find(element_id)
    # Skip if no ID or not within valid range
    if (idx1 != -1 and idx1 < 6):
        idx2 = line.find(bsm_id)
        # Skip if no ID or not within valid range
        if (idx2 != -1 and idx2 < 6):
            return True
    return False

def convertBytes(obj):
    if isinstance(obj, dict):
        return {k: convertBytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convertBytes(item) for item in obj]
    elif isinstance(obj, tuple):
        return [convertBytes(item) for item in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    else:
        return obj

def decode(data, frame, w, msgId_count, id):
    try:
        frame.from_uper(unhexlify(data))
        print(data)
        w.write(data)
        w.write('\n')
        cleanObj = convertBytes(frame())
        jsonString = json.dumps(cleanObj, indent=2)
        print(jsonString)
        w.write(jsonString)
        w.write('\n')
        msgId_count[id] += 1  # increment count for successfully decoded msgId
    except Exception as e:
        print("Error decoding invalid message: ", e)

def main():
    frame = J2735_201603_2023_06_22.DSRC.MessageFrame
    msgIds = ['0012','0013','0014','001f','0020','0029'] # can be updated to include other PSIDs
    msgId_count = defaultdict(int)  # dictionary to track decoded msgId and their counts
    file = browse_file()
    if not file:
        print("No file selected. Exiting.")
        sys.exit(1)
    
    packets = extract_packets(file)
    if not packets:
        print("No UDP packets found in the selected file. Exiting.")
        sys.exit(1)
    
    # Make sure the decoded/ directory exists alongside src/
    srcDir     = os.path.dirname(os.path.abspath(__file__))
    decodedDir = os.path.abspath(os.path.join(srcDir, '..', 'decoded'))
    os.makedirs(decodedDir, exist_ok=True)

    # Build the output path
    decodedFile = formatFileName(file)
    decodedPath     = os.path.join(decodedDir, decodedFile)
    w = open(decodedPath, 'w')

    for line in packets:
        for id in msgIds:
            idx = line.find(id)
            if (idx != -1):
                data = line[idx:]
                if isValidMsgSize(data):
                    if not isBSMPSID(data):
                        decode(data, frame, w, msgId_count, id)

    # Write the decoded message IDs and their counts to the output file
    writeIds(w, msgId_count)
    w.close()

    print('\nDecoding Complete. Check', decodedFile, '\n')
    sys.exit(0)

if __name__=="__main__":
    main()
