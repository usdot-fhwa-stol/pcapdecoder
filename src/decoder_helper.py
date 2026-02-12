import os, pyshark
from binascii import unhexlify
from io import TextIOWrapper
from tkinter import Tk, filedialog
from collections import defaultdict

# Monkey-patch imports to control JSON encoding behavior used by to_jer()
import pycrate_asn1rt.asnobj
import pycrate_core.elt as _core_elt
import pycrate_asn1rt.codecs as _asn_codecs
import json

from pycrate_asn1rt.asnobj_ext import OPEN
from pycrate_asn1rt.asnobj import ASN1Obj
from pycrate_core.base import str_types, bytes_types
from binascii import hexlify

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

# Fix for pycrate OPEN type JER encoding: preserve type wrapper in discriminated unions
# Without this patch, OPEN types lose their type discriminator in JSON output
def _fix_open_to_jval(self):
    """Preserves type wrapper in JER encoding."""
    if isinstance(self._val[0], ASN1Obj):
        Obj = self._val[0]
        type_name = '%s.%s' % (Obj._mod, Obj._name) # Get type name
    else:
        if isinstance(self._val[0], str_types) and self._val[0][:5] == '_unk_':
            if isinstance(self._val[1], bytes_types):
                return hexlify(self._val[1]).decode()
            else:
                return self._val[1]
        Obj = self._get_val_obj(self._val[0])
        type_name = self._val[0] # Get type name
    Obj._val = self._val[1]
    # Return with type wrapper
    return {type_name: Obj._to_jval()}

OPEN._to_jval = _fix_open_to_jval


def output(message: str, w: TextIOWrapper | None = None, newline: bool = True, flush: bool = False) -> None:
    """Unified console and optional file output.

    Parameters:
        message (str): Text to emit.
        w (TextIOWrapper | None): Optional file handle to also write to.
        newline (bool): Append a newline to file output if True.
        flush (bool): Flush file handle after write if True.
    """
    if w:
        w.write(message)
        if newline:
            w.write('\n')
        if flush:
            try:
                w.flush()
            except Exception:
                # Ignore flush errors
                pass

def browse_file() -> str:
    """Open file dialog and return the selected file path
    
    Returns:
        str: The selected file path.
    """
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
    filename = 'decoded_' + file.replace('.pcap', '.log')
    return filename

def extract_packets(pcap_file: str) -> dict[float, list[str]]:
    """Extract hex payloads from a PCAP with their timestamps.

    Parameters:
        pcap_file (str): The path to the PCAP file.

    Returns:
        dict[float, list[str]]: Mapping of packet timestamps to lists of hex payloads.
    """
    output(f'Extracting packets from {pcap_file}...')

    def _clean_hex(s: str | None) -> str | None:
        if not s:
            return None
        # Pyshark may return colon-delimited bytes; strip separators and lower.
        cleaned = s.replace(":", "").replace(" ", "").strip().lower()
        # Try to decode as ASCII
        try:
            decoded = bytes.fromhex(cleaned).decode('ascii')
            # Extract Payload field
            idx = decoded.find('Payload=')
            if idx != -1:
                return decoded[idx+8:].strip().lower()
        except (ValueError, UnicodeDecodeError):
            pass
        return cleaned

    def _extract_payload(packet) -> str | None:
        """Try extracting payload in priority order: data.data > mqtt.msg > raw."""
        if hasattr(packet, 'data') and (data := _clean_hex(getattr(packet.data, 'data', None))):
            return data
        if hasattr(packet, 'mqtt') and (mqtt := _clean_hex(getattr(packet.mqtt, 'msg', None))):
            return mqtt
        if raw := packet.get_raw_packet():
            return raw.hex()
        return None

    packets_by_time: defaultdict[float, list[str]] = defaultdict(list)

    capture = pyshark.FileCapture(
        pcap_file,
        display_filter='udp || wsmp || mqtt',
        use_json=True,
        include_raw=True,
        keep_packets=False,
    )
    try:
        for packet in capture:
            # Use pyshark-provided timestamp
            try:
                ts = float(packet.sniff_timestamp)
            except Exception:
                try:
                    ts = packet.sniff_time.timestamp()
                except Exception:
                    # If no timestamp, skip this packet
                    continue

            if payload := _extract_payload(packet):
                packets_by_time[ts].append(payload)
    finally:
        capture.close()

    output(f'Extracted {sum(len(v) for v in packets_by_time.values())} packets across {len(packets_by_time)} unique timestamps.')
    return dict(packets_by_time)

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
            try:
                p95_ipg = statistics.quantiles(gaps_ms, n=20)[18]  # 95th percentile
                p99_ipg = statistics.quantiles(gaps_ms, n=100)[98]  # 99th percentile
            except statistics.StatisticsError:
                # Fallback for small datasets
                sorted_gaps = sorted(gaps_ms)
                p95_idx = min(int(len(sorted_gaps) * 0.95 + 0.5) - 1, len(sorted_gaps) - 1)
                p99_idx = min(int(len(sorted_gaps) * 0.99 + 0.5) - 1, len(sorted_gaps) - 1)
                p95_ipg = sorted_gaps[p95_idx]
                p99_ipg = sorted_gaps[p99_idx]

            label = f'{msgId.name} ({msgId.value})' if isinstance(msgId, Enum) else str(msgId)
            output(f'{label}:', w)
            output(f'  Packets: {len(timestamps)}', w)
            output(f'  Average IPG: {avg_ipg:.2f} ms', w)
            output(f'  95th percentile: {p95_ipg:.2f} ms', w)
            output(f'  99th percentile: {p99_ipg:.2f} ms', w)

def decode(data: str, frame, w: TextIOWrapper, msgId_count: defaultdict, id: str, timestamp: float, msgId_timestamps: defaultdict) -> None:
    """
    Decodes the given message data and writes the output to the specified file.

    Parameters:
        data (str): The hex-encoded message data to decode.
        frame: The ASN.1 frame object used for decoding.
        w (TextIOWrapper): The output file handle to write decoded data.
        msgId_count (defaultdict): Dictionary tracking the count of each message ID.
        id (str): The message ID associated with the data.
        timestamp (float): The timestamp of the message (seconds since epoch).
        msgId_timestamps (defaultdict): Dictionary mapping message IDs to lists of timestamps.

    Returns:
        None
    """
    try:
        # Convert UPER data to pycrate message frame
        frame.from_uper(unhexlify(data))
        # Generate output string in format <timestamp epoch ms> : <compact json decoded payload>
        output_string = str(round(timestamp * 1000)) # Convert to milliseconds and round to int
        output_string = output_string + " : "
        json_string = frame.to_jer()
        # Remove newlines and tabs for compactness
        json_object = json.loads(json_string)
        compact_json_string = json.dumps(json_object, separators=(',', ':'))
        output_string = output_string  + compact_json_string

        output(output_string, w)
        msgId_count[id] += 1  # increment count for successfully decoded msgId
        msgId_timestamps[id].append(timestamp)
    except Exception as e:
        output(f"Error decoding invalid message: {e}")
