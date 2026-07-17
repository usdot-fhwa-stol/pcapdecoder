import os, pyshark
import contextlib, io
import Ieee1609Dot2
import Ieee1609Dot3Wsm
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

def format_file_name(file: str) -> str:
    """Format the file name for the decoded output.

    Parameters:
        file (str): The original file name.
    Returns:
        str: The formatted file name.
    """
    file = os.path.basename(file)
    filename = 'decoded_' + file.replace('.pcap', '.log')
    return filename

# Maximum number of leading bytes to scan for the start of the WSMP-N-Header.
# Captures wrap the WSM in varying outer framing, so the WSMP
# ShortMsgNpdu does not always begin at offset 0 of the captured payload.
_WSMP_SCAN_BYTES = 64

# First byte of a WSMP-N-Header for the messages we decode: null subtype, no
# N-extensions, version 3 -> UPER encodes to 0x03. Gating the offset scan on
# this byte avoids an expensive ShortMsgNpdu UPER decode attempt at every
# offset while keeping the strict validation below.
_WSMP_FIRST_BYTE = 0x03

_ShortMsgNpdu = Ieee1609Dot3Wsm.Ieee1609Dot3Wsm.ShortMsgNpdu
_Ieee1609Dot2Data = Ieee1609Dot2.Ieee1609Dot2.Ieee1609Dot2Data


def _wsm_from_dot2(dot2data: dict) -> bytes | None:
    """Pull the WSM (J2735 MessageFrame) bytes out of a decoded Ieee1609Dot2Data.

    Handles both content choices seen on the wire:
      - unsecuredData: the WSM is the Opaque payload directly.
      - signedData: the WSM is the unsecured payload nested in tbsData.
    """
    choice, value = dot2data['content']
    if choice == 'unsecuredData':
        return value
    if choice == 'signedData':
        inner = value['tbsData']['payload']['data']  # nested Ieee1609Dot2Data
        inner_choice, inner_value = inner['content']
        if inner_choice == 'unsecuredData':
            return inner_value
    return None


def get_wsm(data: str) -> str | None:
    """Extract the WSM (J2735 MessageFrame) hex from a captured UDP payload.

    The payload is a WSMP frame (IEEE 1609.3 ShortMsgNpdu) carrying
    Ieee1609Dot2Data, which carries the WSM. Because the outer framing
    varies by capture source, the first bytes are scanned for a *valid*
    WSMP-N-Header (null subtype, version 3, bcMode transport) whose body
    OER-decodes to a known Ieee1609Dot2Data content type.

    Parameters:
        data (str): Hex-encoded UDP payload.
    Returns:
        str | None: The WSM hex, or None if no WSM could be extracted.
    """
    raw = unhexlify(data.strip())
    # pycrate emits decode warnings to stdout/stderr on the many failed probe
    # attempts; silence them so the scan stays quiet.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        for offset in range(min(_WSMP_SCAN_BYTES, len(raw))):
            if raw[offset] != _WSMP_FIRST_BYTE:
                continue
            try:
                _ShortMsgNpdu.reset_val()
                _ShortMsgNpdu.from_uper(raw[offset:])
                npdu = _ShortMsgNpdu()
            except Exception:
                continue
            # Validate this is a well-formed WSMP-N-Header, not a chance parse.
            subtype, subtype_val = npdu['subtype']
            if subtype != 'nullNetworking' or subtype_val.get('version') != 3:
                continue
            if npdu['transport'][0] != 'bcMode' or not npdu['body']:
                continue
            try:
                _Ieee1609Dot2Data.reset_val()
                _Ieee1609Dot2Data.from_oer(npdu['body'])
                dot2data = _Ieee1609Dot2Data()
            except Exception:
                continue
            if dot2data['content'][0] not in ('unsecuredData', 'signedData'):
                continue
            wsm = _wsm_from_dot2(dot2data)
            if wsm:
                return wsm.hex()
    return None

def extract_packets(pcap_file: str) -> dict[float, list[str]]:
    """Extract WSM (J2735 MessageFrame) hex payloads from a PCAP with timestamps.

    Each UDP payload is unwrapped through its WSMP (1609.3) and Ieee1609Dot2Data
    layers down to the WSM via get_wsm. Non-WSMP packets are skipped.

    Parameters:
        pcap_file (str): The path to the PCAP file.

    Returns:
        dict[float, list[str]]: Mapping of packet timestamps to lists of WSM hex.
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
        except (ValueError):
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

            # Extract the raw UDP payload, then unwrap WSMP + 1609.2 to the WSM.
            # Packets that are not WSMP-framed WSMs yield None and are dropped.
            if (payload := _extract_payload(packet)) and (wsm := get_wsm(payload)):
                packets_by_time[ts].append(wsm)
    finally:
        capture.close()

    output(f'Extracted {sum(len(v) for v in packets_by_time.values())} WSMs across {len(packets_by_time)} unique timestamps.')
    return dict(packets_by_time)

def write_ids(w: TextIOWrapper, msg_id_count: defaultdict[int, int]) -> None:
    """Write the decoded message IDs and their counts to the output file.

    Parameters:
        w (TextIOWrapper): The output file handle.
        msg_id_count (defaultdict[int, int]): The message ID counts.
    """
    from enum import Enum
    output('\nDecoded Message ID Counts:', w)
    for msg_id, count in msg_id_count.items():
        # Format Enum members as "NAME (value)", otherwise just the value
        if isinstance(msg_id, Enum):
            output(f'{msg_id.name} ({msg_id.value}): {count}', w)
        else:
            output(f'{msg_id}: {count}', w)

def writeIpgStats(w: TextIOWrapper, msg_id_timestamps: defaultdict[str, list[float]]) -> None:
    """Calculate and write inter-packet gap statistics for each message ID.

    Parameters:
        w (TextIOWrapper): The output file handle.
        msg_id_timestamps (defaultdict[str, list[float]]): Timestamps for each msg_id.
    """
    import statistics
    
    from enum import Enum
    output('\nInter-Packet Gap Statistics (milliseconds):', w)
    output('-' * 60, w)
    
    # Sort by Enum name if available, otherwise by string representation
    sorted_keys = sorted(msg_id_timestamps.keys(), 
                        key=lambda x: x.name if isinstance(x, Enum) else str(x))
    
    for msg_id in sorted_keys:
        timestamps = sorted(msg_id_timestamps[msg_id])
        if len(timestamps) < 2:
            label = f'{msg_id.name} ({msg_id.value})' if isinstance(msg_id, Enum) else str(msg_id)
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

            label = f'{msg_id.name} ({msg_id.value})' if isinstance(msg_id, Enum) else str(msg_id)
            output(f'{label}:', w)
            output(f'  Packets: {len(timestamps)}', w)
            output(f'  Average IPG: {avg_ipg:.2f} ms', w)
            output(f'  95th percentile: {p95_ipg:.2f} ms', w)
            output(f'  99th percentile: {p99_ipg:.2f} ms', w)

def decode(data: str, frame, w: TextIOWrapper, msg_id_count: defaultdict, id: str, timestamp: float, msg_id_timestamps: defaultdict) -> None:
    """
    Decodes the given message data and writes the output to the specified file.

    Parameters:
        data (str): The hex-encoded message data to decode.
        frame: The ASN.1 frame object used for decoding.
        w (TextIOWrapper): The output file handle to write decoded data.
        msg_id_count (defaultdict): Dictionary tracking the count of each message ID.
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
        msg_id_count[id] += 1  # increment count for successfully decoded msgId
        msg_id_timestamps[id].append(timestamp)
    except Exception as e:
        output(f"Error decoding invalid message: {e}")
