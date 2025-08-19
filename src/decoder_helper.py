import os, pyshark
from binascii import unhexlify
from io import TextIOWrapper
from tkinter import Tk, filedialog
from collections import defaultdict

# Monkey-patch imports to control JSON encoding behavior used by to_jer()
import pycrate_asn1rt.asnobj
import pycrate_core.elt as _core_elt
import pycrate_asn1rt.codecs as _asn_codecs

# Ensure JER JSON preserves insertion order (disable alphabetical sorting)
# i.e., pycrate defaults to JSONEncoder(sort_keys=True). Override it here.
try:
    # Recreate the encoder with sort_keys disabled
    _core_elt.JsonEnc = _core_elt.JSONEncoder(sort_keys=False, indent=1)
    # Propagate to modules that cached the encoder
    _asn_codecs.JsonEnc = _core_elt.JsonEnc
    pycrate_asn1rt.asnobj.JsonEnc = _core_elt.JsonEnc
except Exception:
    pass

def browse_file() -> str:
    """Open file dialog and return the selected file path"""
    root = Tk()
    root.withdraw()
    srcDir = os.path.dirname(os.path.abspath(__file__))
    logDir = os.path.join(srcDir, '../logs')
    filename = filedialog.askopenfilename(initialdir=logDir,
                                          title = "Select a File",
                                          filetypes=[("PCAP Files", "*.pcap")])
    return filename

def formatFileName(file: str) -> str:
    """Format the file name for the decoded output.

    Parameters:
        file (str): The original file name.
    Returns:
        str: The formatted file name.
    """
    file = os.path.basename(file)
    fileName = 'decoded_' + file.replace('.pcap', '.txt')
    return fileName

def extract_packets(pcap_file: str) -> list[str]:
    """Extract packets from the PCAP file.

    Parameters:
        pcap_file (str): The path to the PCAP file.
    Returns:
        list[str]: A list of extracted packet data.
    """
    capture = pyshark.FileCapture(pcap_file, display_filter='udp')
    packets = []
    for packet in capture:
        try:
            packets.append(packet.data.data)
        except AttributeError:
            continue
    return packets

def writeIds(w: TextIOWrapper, msgId_count: defaultdict[int, int]) -> None:
    """Write the decoded message IDs and their counts to the output file.

    Parameters:
        w (TextIOWrapper): The output file handle.
        msgId_count (defaultdict[int, int]): The message ID counts.
    """
    w.write('\nDecoded Message ID Counts:\n')
    print('\nDecoded Message ID Counts:')
    for msgId, count in msgId_count.items():
        w.write(f'{msgId}: {count}\n')
        print(f'{msgId}: {count}')

def isValidMsgSize(line: str) -> bool:
    """Checks actual message size against size specified in MessageFrame.

    Parameters:
        line (str): Full message under test
    Returns:
        bool: True if the message size is valid, False otherwise.
    """
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

def isSigned(frame: str) -> bool:
    """Checks if the message is signed by looking for a certificate or digest hash.

    Parameters:
        frame (str): The message frame under test.
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

def isBSMPSID(line: str) -> bool:
    """Check to ensure a found BSM PSID (0x0020) is not actually PSM DSRCmsgID 32 (0x0020). This is done by looking for the Element ID (0x0380),
    followed by the BSM DSRCmsgID 20 (0x0014). Specifically, looking for 0020...0380...0014, else false.

    Parameters:
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

def decode(data: str, frame, w: TextIOWrapper, msgId_count: defaultdict, id: str):
    """
    Decodes the given message data and writes the output to the specified file.
    """
    try:
        frame.from_uper(unhexlify(data))
        print(data)
        w.write(data)
        w.write('\n')
        jsonString = frame.to_jer()
        print(jsonString)
        w.write(jsonString)
        w.write('\n')
        msgId_count[id] += 1  # increment count for successfully decoded msgId
    except Exception as e:
        print("Error decoding invalid message: ", e)
