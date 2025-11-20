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

def output(message: str, w: TextIOWrapper | None = None, newline: bool = True, flush: bool = False) -> None:
    """Unified console and optional file output.

    Parameters:
        message (str): Text to emit.
        w (TextIOWrapper | None): Optional file handle to also write to.
        newline (bool): Append a newline to file output if True.
        flush (bool): Flush file handle after write if True.
    """
    print(message)
    if w:
        w.write(message)
        if newline:
            w.write('\n')
        if flush:
            try:
                w.flush()
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

def extract_packets(pcap_file: str) -> dict[float, list[str]]:
    """Extract hex payloads from a PCAP with their timestamps.

    Returns a mapping of packet timestamp (epoch seconds) to a list of one or
    more hex payload strings observed at that exact timestamp. Multiple payloads
    can share the same timestamp at sub-second precision depending on capture.
    """
    output(f'Extracting packets from {pcap_file}...')
    def _clean_hex(s: str | None) -> str | None:
        if not s:
            return None
        # Pyshark may return colon-delimited bytes; strip separators and lower.
        return s.replace(":", "").replace(" ", "").strip().lower()

    packets_by_time: dict[float, list[str]] = {}

    # One pass: include raw for reliable fallback; keep_packets=False for low RAM.
    capture = pyshark.FileCapture(
        pcap_file,
        display_filter='udp || wsmp',
        use_json=True,
        include_raw=True,
        keep_packets=False,
    )
    try:
        for packet in capture:
            # Use pyshark-provided timestamp; prefer numeric seconds for stability
            try:
                ts = float(packet.sniff_timestamp)
            except Exception:
                try:
                    ts = packet.sniff_time.timestamp()  # type: ignore[attr-defined]
                except Exception:
                    # If no timestamp, skip this packet
                    continue

            appended = False
            # If available, get udp data.data field
            try:
                if hasattr(packet, 'data'):
                    data_field = getattr(packet.data, 'data', None)
                    data_field = _clean_hex(data_field)
                    if data_field:
                        packets_by_time.setdefault(ts, []).append(data_field)
                        appended = True
                        continue
            except Exception:
                pass

            # Else get raw packet
            if not appended:
                try:
                    raw = packet.get_raw_packet()
                    if raw:
                        packets_by_time.setdefault(ts, []).append(raw.hex())
                except Exception:
                    # As a last resort, skip this packet
                    continue
    finally:
        try:
            capture.close()
        except Exception:
            pass

    output(f'Extracted {sum(len(v) for v in packets_by_time.values())} packets across {len(packets_by_time)} unique timestamps.')
    return packets_by_time

def writeIds(w: TextIOWrapper, msgId_count: defaultdict[int, int]) -> None:
    """Write the decoded message IDs and their counts to the output file.

    Parameters:
        w (TextIOWrapper): The output file handle.
        msgId_count (defaultdict[int, int]): The message ID counts.
    """
    from enum import Enum
    output('\nDecoded Message ID Counts:', w)
    for msgId, count in msgId_count.items():
        # Format Enum members as "NAME (value)", otherwise just the value
        if isinstance(msgId, Enum):
            output(f'{msgId.name} ({msgId.value}): {count}', w)
        else:
            output(f'{msgId}: {count}', w)

def writeIpgStats(w: TextIOWrapper, msgId_timestamps: defaultdict[str, list[float]]) -> None:
    """Calculate and write inter-packet gap statistics for each message ID.

    Parameters:
        w (TextIOWrapper): The output file handle.
        msgId_timestamps (defaultdict[str, list[float]]): Timestamps for each msgId.
    """
    import statistics
    
    from enum import Enum
    output('\nInter-Packet Gap Statistics (milliseconds):', w)
    output('-' * 60, w)
    
    # Sort by Enum name if available, otherwise by string representation
    sorted_keys = sorted(msgId_timestamps.keys(), 
                        key=lambda x: x.name if isinstance(x, Enum) else str(x))
    
    for msgId in sorted_keys:
        timestamps = sorted(msgId_timestamps[msgId])
        if len(timestamps) < 2:
            label = f'{msgId.name} ({msgId.value})' if isinstance(msgId, Enum) else str(msgId)
            output(f'{label}: Insufficient data (only {len(timestamps)} packet)', w)
            continue
        
        # Calculate inter-packet gaps in milliseconds
        gaps_ms = [(timestamps[i+1] - timestamps[i]) * 1000 
                   for i in range(len(timestamps) - 1)]
        
        if gaps_ms:
            avg_ipg = statistics.mean(gaps_ms)
            # Use quantiles for percentiles
            try:
                p95_ipg = statistics.quantiles(gaps_ms, n=20)[18]  # 95th percentile (19/20)
                p99_ipg = statistics.quantiles(gaps_ms, n=100)[98]  # 99th percentile (99/100)
            except statistics.StatisticsError:
                # Fallback for small datasets
                sorted_gaps = sorted(gaps_ms)
                p95_ipg = sorted_gaps[int(len(sorted_gaps) * 0.95)]
                p99_ipg = sorted_gaps[int(len(sorted_gaps) * 0.99)]
            
            label = f'{msgId.name} ({msgId.value})' if isinstance(msgId, Enum) else str(msgId)
            output(f'{label}:', w)
            output(f'  Packets: {len(timestamps)}', w)
            output(f'  Average IPG: {avg_ipg:.2f} ms', w)
            output(f'  95th percentile: {p95_ipg:.2f} ms', w)
            output(f'  99th percentile: {p99_ipg:.2f} ms', w)

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
        output("Valid message.")
        return True
    elif (encodedSize < len(newFrame) + 150):
        output("Checking for certificate or digest hash.")
        # If the message is larger than expected, it may contain a certificate or digest hash
        if isSigned(newFrame):
            output("Message is signed, continuing.")
            return True
    else:
        output("Not a valid message, continuing.")
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
            output(f"Found certificate hash: {fullCert}")
            return True

    if ((possibleDigest[0:2] == possibleDigest[18:20]) and possibleDigest[18:20] == "80"):
        hashId = possibleDigest[2:18]
        if hashId:
            output(f"Found digest hash: {hashId}")
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

def decode(data: str, frame, w: TextIOWrapper, msgId_count: defaultdict, id: str, timestamp: float, msgId_timestamps: defaultdict) -> None:
    """
    Decodes the given message data and writes the output to the specified file.
    """
    try:
        frame.from_uper(unhexlify(data))
        output(data, w)
        jsonString = frame.to_jer()
        output(jsonString, w)
        msgId_count[id] += 1  # increment count for successfully decoded msgId
        if timestamp is not None and msgId_timestamps is not None:
            msgId_timestamps[id].append(timestamp)
        else:
            output("Timestamp or msgId_timestamps is None, cannot record timestamp.")
    except Exception as e:
        output(f"Error decoding invalid message: {e}")
