#!/usr/bin/env python3
"""Multi-stage latency analysis for secured (IEEE 1609.2 signed) BSMs.

Matches each SPDU sent by DUT1 through proxy1 rx, proxy2 tx and DUT2 rx by its
1609.2 signature, and writes a CSV with per-stage timestamps and latencies
relative to the DUT1 send time.
"""
import argparse
import contextlib
import csv
import io
import ipaddress
import statistics
import struct
import sys
from collections import defaultdict
from pathlib import Path

from decoder_helper import decoded_j2735_from_secured

STAGES = ["dut1", "proxy1", "proxy2", "dut2"]

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_WSMP = 0x88DC

IPPROTO_UDP = 17

# pcap magic -> (struct byte order, timestamp fraction divisor)
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}


def read_pcap(path: Path):
    """Yield (timestamp, frame bytes, linktype) for each record of a classic libpcap file.

    Parameters:
        path (Path): Path to the pcap file.
    """
    data = path.read_bytes()
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        raise ValueError(f"{path} is pcapng; convert it with 'editcap -F pcap' first.")
    if magic not in PCAP_MAGIC:
        raise ValueError(f"{path} is not a pcap file (magic {magic.hex()}).")
    endian, divisor = PCAP_MAGIC[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]

    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, cap_len, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        yield ts_sec + ts_frac / divisor, data[off:off + cap_len], linktype
        off += cap_len


def _udp_payload(ethertype: int, l3: bytes) -> tuple[bytes | None, set, set]:
    """Return (UDP payload, {src IP}, {dst IP}) of an IPv4/IPv6 packet; payload is None if not UDP."""
    if ethertype == ETHERTYPE_IPV6 and len(l3) >= 48:
        src, dst = {ipaddress.IPv6Address(l3[8:24])}, {ipaddress.IPv6Address(l3[24:40])}
        return (l3[48:] if l3[6] == IPPROTO_UDP else None), src, dst
    if ethertype == ETHERTYPE_IPV4 and len(l3) >= 20:
        src, dst = {ipaddress.IPv4Address(l3[12:16])}, {ipaddress.IPv4Address(l3[16:20])}
        ihl = (l3[0] & 0x0F) * 4
        return (l3[ihl + 8:] if l3[9] == IPPROTO_UDP else None), src, dst
    return None, set(), set()


def parse_frame(frame: bytes, linktype: int) -> tuple[bytes | None, set, set]:
    """Return (bytes carrying the WSMP, source addresses, destination addresses).

    The WSMP bytes may carry a short prefix and are None for non-WSMP frames. Addresses are
    MAC strings (Ethernet) and ipaddress objects (IP), normalised the same way as parse_address().

    Parameters:
        frame (bytes): Link-layer frame.
        linktype (int): pcap link type of the capture.
    """
    src: set = set()
    dst: set = set()
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None, src, dst
        ethertype = struct.unpack(">H", frame[14:16])[0]
        l3 = frame[16:]
    elif linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None, src, dst
        dst.add(frame[0:6].hex(":"))
        src.add(frame[6:12].hex(":"))
        ethertype = struct.unpack(">H", frame[12:14])[0]
        l3 = frame[14:]
        if ethertype == ETHERTYPE_VLAN and len(l3) >= 4:
            ethertype = struct.unpack(">H", l3[2:4])[0]
            l3 = l3[4:]
    else:
        return None, src, dst

    if ethertype == ETHERTYPE_WSMP:
        return l3, src, dst
    payload, ip_src, ip_dst = _udp_payload(ethertype, l3)
    return payload, src | ip_src, dst | ip_dst


def parse_address(text: str):
    """Normalise an IPv4/IPv6 or MAC address given on the command line."""
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    mac = text.lower().replace("-", ":")
    if len(mac.split(":")) != 6:
        raise argparse.ArgumentTypeError(f"not an IP or MAC address: {text}")
    return ":".join(f"{int(b, 16):02x}" for b in mac.split(":"))


def signature_hex(signature: dict) -> str:
    """Flatten a JER-decoded 1609.2 Signature into a hex string (rSig value + sSig).

    Parameters:
        signature (dict): e.g. {'ecdsaNistP256Signature': {'rSig': {'x-only': ..}, 'sSig': ..}}
    """
    (ecdsa,) = signature.values()
    (r_sig,) = ecdsa["rSig"].values()
    if isinstance(r_sig, dict):  # uncompressedP256 {x, y}
        r_sig = r_sig["x"] + r_sig["y"]
    return r_sig + ecdsa["sSig"]


def load_stage(path: Path, src: list | None = None, dst: list | None = None) -> dict[str, list[dict]]:
    """Decode every signed BSM in a pcap and group them by signature.

    Parameters:
        path (Path): Path to the pcap file.
        src (list | None): If given, keep only packets whose source address is one of these.
        dst (list | None): If given, keep only packets whose destination address is one of these.

    Returns:
        dict[str, list[dict]]: signature hex -> occurrences sorted by timestamp.
    """
    sig_to_data: defaultdict[str, list[dict]] = defaultdict(list)
    n_filtered = 0
    for ts, frame, linktype in read_pcap(path):
        payload, frame_src, frame_dst = parse_frame(frame, linktype)
        if not payload:
            continue
        if (src and frame_src.isdisjoint(src)) or (dst and frame_dst.isdisjoint(dst)):
            n_filtered += 1
            continue
        # decoded_j2735_from_secured prints an error for every non-BSM / unsecured packet
        with contextlib.redirect_stdout(io.StringIO()):
            wsmp, ieee1609dot2_data, j2735_data = decoded_j2735_from_secured(payload.hex())
        if j2735_data is None:
            continue
        try:
            sig = signature_hex(ieee1609dot2_data["content"]["signedData"]["signature"])
        except (KeyError, TypeError, ValueError):
            continue
        sig_to_data[sig].append({
            "timestamp": ts,
            "spdu": wsmp["body"],
            "wsmp": wsmp,
            "ieee1609dot2": ieee1609dot2_data,
            "j2735": j2735_data,
        })

    for entries in sig_to_data.values():
        entries.sort(key=lambda e: e["timestamp"])
    filters = ", ".join(f"{name} in {{{', '.join(map(str, addrs))}}}"
                        for name, addrs in (("src", src), ("dst", dst)) if addrs)
    print(f"  {path.name}: {sum(len(v) for v in sig_to_data.values())} signed BSMs, "
          f"{len(sig_to_data)} unique signatures"
          + (f" (kept {filters}; dropped {n_filtered} packets)" if filters else ""))
    return dict(sig_to_data)


def match(stages: dict[str, dict[str, list[dict]]]) -> list[dict]:
    """Match each DUT1 signature to its first occurrence at every downstream stage.

    Matching is by signature only; no ordering in time is assumed, so clock offsets between
    capture hosts show up as anomalies (see find_anomalies) instead of silently dropping matches.

    Parameters:
        stages (dict): stage name -> signature map from load_stage() (already source-filtered).

    Returns:
        list[dict]: one row per DUT1 signature, sorted by DUT1 send time.
    """
    rows = []
    for sig, dut1_entries in stages["dut1"].items():
        first = dut1_entries[0]
        t_dut1 = first["timestamp"]
        row = {"signature": sig, "spdu_hex": first["spdu"], "t_dut1": t_dut1}
        for stage in STAGES[1:]:
            entries = stages[stage].get(sig)
            hit = entries[0] if entries else None
            row[f"t_{stage}"] = hit["timestamp"] if hit else None
            row[f"lat_{stage}_ms"] = (hit["timestamp"] - t_dut1) * 1000 if hit else None
            row[f"spdu_{stage}"] = hit["spdu"] if hit else None
        for stage in STAGES:
            row[f"n_{stage}"] = len(stages[stage].get(sig, []))
        row["anomalies"] = find_anomalies(row)
        rows.append(row)
    rows.sort(key=lambda r: r["t_dut1"])
    return rows


def find_anomalies(row: dict) -> list[str]:
    """Return anomaly tags for one matched row.

    Tags:
        missing:<stage>       signature never seen at that stage
        negative:<stage>      stage timestamp earlier than the DUT1 send (clock offset?)
        order:<a>><b>         stage b seen before the earlier stage a
        spdu_mismatch:<stage> same signature but different SPDU bytes than DUT1 sent
    """
    tags = []
    prev_stage, prev_t = "dut1", row["t_dut1"]
    for stage in STAGES[1:]:
        t = row[f"t_{stage}"]
        if t is None:
            tags.append(f"missing:{stage}")
            continue
        if t < row["t_dut1"]:
            tags.append(f"negative:{stage}")
        elif t < prev_t:
            tags.append(f"order:{prev_stage}>{stage}")
        if row[f"spdu_{stage}"] != row["spdu_hex"]:
            tags.append(f"spdu_mismatch:{stage}")
        prev_stage, prev_t = stage, t
    return tags


def report_anomalies(rows: list[dict], stages: dict[str, dict[str, list[dict]]], examples: int = 5) -> None:
    """Print anomaly counts per type, a few examples, and downstream-only signatures."""
    print("\nMatching anomalies:")
    print("-" * 72)
    by_tag: defaultdict[str, list[dict]] = defaultdict(list)
    for r in rows:
        for tag in r["anomalies"]:
            by_tag[tag].append(r)
    if not by_tag:
        print("  none")
    for tag in sorted(by_tag):
        hits = by_tag[tag]
        print(f"  {tag}: {len(hits)}")
        stage = tag.split(":", 1)[1].split(">")[-1]
        for r in hits[:examples]:
            lat = r.get(f"lat_{stage}_ms")
            detail = f"{stage} latency {lat:.3f} ms" if lat is not None else "no copy"
            print(f"      {r['signature'][:16]}...  DUT1 t={r['t_dut1']:.6f}  {detail}")
        if len(hits) > examples:
            print(f"      ... {len(hits) - examples} more (see 'anomalies' column in the CSV)")

    dut1_sigs = stages["dut1"].keys()
    for stage in STAGES[1:]:
        extra = len(stages[stage].keys() - dut1_sigs)
        if extra:
            print(f"  {stage}: {extra} signatures not sent by DUT1 (other senders or filtered-out DUT1 copies)")


def report_duplicates(stages: dict[str, dict[str, list[dict]]], top: int = 10) -> None:
    """Print how often the same signed SPDU was captured more than once at each stage."""
    print("\nRepeated SPDUs (same signature captured more than once):")
    print("-" * 72)
    for stage in STAGES:
        counts = [len(v) for v in stages[stage].values()]
        repeated = [c for c in counts if c > 1]
        mean = statistics.mean(counts) if counts else 0
        print(f"{stage:>7}: {len(counts)} unique, {sum(counts)} total, {len(repeated)} repeated, "
              f"max {max(counts, default=0)}x, mean {mean:.2f}x")

    worst = sorted(stages["dut1"].items(), key=lambda kv: len(kv[1]), reverse=True)[:top]
    if worst and len(worst[0][1]) > 1:
        print(f"\nMost repeated DUT1 signatures (gaps between sends, ms):")
        for sig, entries in worst:
            if len(entries) < 2:
                break
            ts = [e["timestamp"] for e in entries]
            gaps = ", ".join(f"{(b - a) * 1000:.1f}" for a, b in zip(ts, ts[1:]))
            print(f"  {sig[:16]}... {len(entries)}x  [{gaps}]")


def report_latency(rows: list[dict]) -> None:
    """Print latency statistics per stage."""
    print("\nLatency relative to DUT1 send time (ms):")
    print("-" * 72)
    for stage in STAGES[1:]:
        lat = sorted(r[f"lat_{stage}_ms"] for r in rows if r[f"lat_{stage}_ms"] is not None)
        if not lat:
            print(f"{stage:>7}: no matches")
            continue
        p95 = lat[min(len(lat) - 1, int(round(0.95 * len(lat))) - 1)]
        print(f"{stage:>7}: matched {len(lat)}/{len(rows)}  min {lat[0]:.2f}  "
              f"median {statistics.median(lat):.2f}  mean {statistics.mean(lat):.2f}  "
              f"p95 {p95:.2f}  max {lat[-1]:.2f}")


STAGE_LABELS = {"proxy1": "Proxy1 rx", "proxy2": "Proxy2 tx", "dut2": "DUT2 rx"}

# Plot styling: one series colour, recessive text/grid
_SERIES = "#2a78d6"
# Categorical slots 1-3 (validated all-pairs); DUT1 is the 0 ms reference, drawn in neutral ink
STAGE_COLORS = {"dut1": "#52514e", "proxy1": "#2a78d6", "proxy2": "#eb6834", "dut2": "#1baf7a"}
_SURFACE = "#fcfcfb"
_TEXT = "#0b0b0b"
_TEXT_2 = "#52514e"
_GRID = "#e4e3df"


def _style_axes(ax) -> None:
    ax.set_facecolor(_SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(_TEXT_2)
    ax.tick_params(colors=_TEXT_2, labelcolor=_TEXT_2)
    ax.grid(color=_GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _boxplot(ax, data, color: str = _SERIES, **kwargs):
    return ax.boxplot(
        data, widths=0.5, patch_artist=True, showfliers=True,
        boxprops=dict(facecolor=color + "33", edgecolor=color, linewidth=1.5),
        medianprops=dict(color=color, linewidth=2),
        whiskerprops=dict(color=color, linewidth=1.5),
        capprops=dict(color=color, linewidth=1.5),
        flierprops=dict(marker="o", markersize=4, markerfacecolor="none",
                        markeredgecolor=color, alpha=0.7),
        **kwargs)


def _percentile(sorted_vals: list[float], q: float) -> float:
    return sorted_vals[min(len(sorted_vals) - 1, max(0, int(round(q * len(sorted_vals))) - 1))]


def plot_latency(rows: list[dict], out_dir: Path, stem: str) -> list[Path]:
    """Plot latency figures and save them as PNGs.

    1. End-to-end (DUT1 -> DUT2) latency: histogram with a boxplot (outliers shown) above it.
    2. Latency by stage relative to the DUT1 send time: one horizontal boxplot per stage.
    3. Per-message latency: one row per message with a dot per stage at its latency,
       rows sorted by end-to-end latency (lowest on top).

    Parameters:
        rows (list[dict]): Output of match().
        out_dir (Path): Directory to write the PNGs into.
        stem (str): File name prefix.

    Returns:
        list[Path]: Paths of the written figures.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.size": 10, "text.color": _TEXT, "axes.labelcolor": _TEXT_2})
    lat = {s: sorted(r[f"lat_{s}_ms"] for r in rows if r[f"lat_{s}_ms"] is not None)
           for s in STAGES[1:]}
    written = []

    # 1. End-to-end histogram + boxplot
    e2e = lat["dut2"]
    if e2e:
        fig, (ax_box, ax_hist) = plt.subplots(
            2, 1, sharex=True, figsize=(8, 5), dpi=300, facecolor=_SURFACE,
            gridspec_kw=dict(height_ratios=[1, 4], hspace=0.05))
        _boxplot(ax_box, e2e, vert=False)
        ax_box.set_yticks([])
        ax_box.grid(axis="y", visible=False)

        bin_ms = 5
        lo, hi = bin_ms * int(e2e[0] // bin_ms), bin_ms * (int(e2e[-1] // bin_ms) + 1)
        ax_hist.hist(e2e, bins=range(lo, hi + bin_ms, bin_ms), color=_SERIES,
                     edgecolor=_SURFACE, linewidth=0.5)
        ax_hist.grid(axis="x", visible=False)

        median, p95 = statistics.median(e2e), _percentile(e2e, 0.95)
        # Stagger the two labels vertically so they never collide
        for value, name, dy in ((median, "median", -4), (p95, "p95", -20)):
            ax_hist.axvline(value, color=_TEXT_2, linestyle="--", linewidth=1)
            ax_hist.annotate(f"{name} {value:.1f} ms", xy=(value, 1), xycoords=("data", "axes fraction"),
                             xytext=(4, dy), textcoords="offset points", va="top",
                             color=_TEXT_2, fontsize=9)
        ax_hist.set_xlabel("End-to-end latency, DUT1 send → DUT2 receive (ms)")
        ax_hist.set_ylabel(f"Messages per {bin_ms} ms bin")
        for ax in (ax_box, ax_hist):
            _style_axes(ax)
        ax_box.grid(axis="y", visible=False)
        ax_hist.grid(axis="x", visible=False)
        fig.suptitle(f"End-to-end latency (n={len(e2e)}, "
                     f"{len(rows) - len(e2e)} not received)", x=0.125, ha="left", color=_TEXT)
        path = out_dir / f"{stem}_e2e_latency.png"
        fig.savefig(path, bbox_inches="tight", facecolor=_SURFACE)
        plt.close(fig)
        written.append(path)

    # Plots 2 and 3 share the x range so they can be read side by side
    all_lat = [v for s in STAGES[1:] for v in lat[s]]
    x_max = max(all_lat, default=1) * 1.03
    x_min = min(0, min(all_lat, default=0)) - 0.03 * x_max

    # 2. Horizontal boxplot by stage, top to bottom in stage order
    stages = [s for s in STAGES[1:] if lat[s]]
    if stages:
        fig, ax = plt.subplots(figsize=(8, 4), dpi=150, facecolor=_SURFACE)
        positions = list(range(len(stages), 0, -1))
        for pos, s in zip(positions, stages):
            _boxplot(ax, [lat[s]], color=STAGE_COLORS[s], positions=[pos], vert=False)
            median = statistics.median(lat[s])
            ax.annotate(f"median {median:.1f}", xy=(median, pos + 0.3), ha="left", va="bottom",
                        color=_TEXT_2, fontsize=9)
        ax.set_yticks(positions, [f"{STAGE_LABELS[s]}\n(n={len(lat[s])})" for s in stages])
        ax.set_ylim(0.4, len(stages) + 0.8)
        ax.set_xlim(x_min, x_max)
        _style_axes(ax)
        ax.grid(axis="y", visible=False)
        ax.set_xlabel("Latency from DUT1 send (ms)")
        ax.set_title("Latency by stage (outliers shown)", loc="left", color=_TEXT)
        path = out_dir / f"{stem}_latency_by_stage.png"
        fig.savefig(path, bbox_inches="tight", facecolor=_SURFACE)
        plt.close(fig)
        written.append(path)

    # 3. Per-message dot plot, sorted by end-to-end latency; messages DUT2 never got go last
    def _sort_key(r):
        e2e_ms = r["lat_dut2_ms"]
        reached = [r[f"lat_{s}_ms"] for s in STAGES[1:] if r[f"lat_{s}_ms"] is not None]
        return (e2e_ms is None, e2e_ms if e2e_ms is not None else max(reached, default=0))

    ordered = sorted(rows, key=_sort_key)
    if ordered:
        fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150, facecolor=_SURFACE)
        rank = range(len(ordered))
        ax.scatter([0] * len(ordered), rank, s=4, color=STAGE_COLORS["dut1"], linewidths=0,
                   label="DUT1 tx (0 ms reference)")
        for s in STAGES[1:]:
            ys = [i for i, r in zip(rank, ordered) if r[f"lat_{s}_ms"] is not None]
            xs = [r[f"lat_{s}_ms"] for r in ordered if r[f"lat_{s}_ms"] is not None]
            ax.scatter(xs, ys, s=4, color=STAGE_COLORS[s], linewidths=0,
                       label=f"{STAGE_LABELS[s]} (n={len(xs)})")
        ax.set_xlim(x_min, x_max)
        ax.set_ylim(len(ordered), -1)  # lowest latency on top
        _style_axes(ax)
        ax.grid(axis="y", visible=False)
        ax.set_xlabel("Latency from DUT1 send (ms)")
        ax.set_ylabel("Message rank by end-to-end latency (lowest on top)")
        ax.set_title(f"Per-message latency at each stage (n={len(ordered)})", loc="left", color=_TEXT)
        legend = ax.legend(loc="upper right", frameon=False, markerscale=3, labelcolor=_TEXT_2)
        path = out_dir / f"{stem}_latency_per_message.png"
        fig.savefig(path, bbox_inches="tight", facecolor=_SURFACE)
        plt.close(fig)
        written.append(path)

    return written


def _fmt(value, digits: int) -> str:
    return "" if value is None else f"{value:.{digits}f}"


def write_csv(rows: list[dict], out_path: Path) -> None:
    """Write the per-signature latency table."""
    header = (["signature", "spdu_hex"]
              + [f"t_{s}" for s in STAGES]
              + [f"lat_{s}_ms" for s in STAGES[1:]]
              + [f"n_{s}" for s in STAGES]
              + ["anomalies"])
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([r["signature"], r["spdu_hex"]]
                       + [_fmt(r[f"t_{s}"], 6) for s in STAGES]
                       + [_fmt(r[f"lat_{s}_ms"], 3) for s in STAGES[1:]]
                       + [r[f"n_{s}"] for s in STAGES]
                       + [";".join(r["anomalies"])])


def write_duplicates_csv(stages: dict[str, dict[str, list[dict]]], out_path: Path) -> int:
    """Write one row per DUT1 signature sent more than once, with all timestamps per stage."""
    dups = sorted(((sig, e) for sig, e in stages["dut1"].items() if len(e) > 1),
                  key=lambda kv: kv[1][0]["timestamp"])
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["signature"] + [f"n_{s}" for s in STAGES] + [f"ts_{s}" for s in STAGES])
        for sig, _ in dups:
            entries = [stages[s].get(sig, []) for s in STAGES]
            w.writerow([sig] + [len(e) for e in entries]
                       + [";".join(f"{x['timestamp']:.6f}" for x in e) for e in entries])
    return len(dups)


def main():
    parser = argparse.ArgumentParser(description="Secured BSM multi-stage latency analysis")
    parser.add_argument("--data-root", default=".", help="Directory containing the pcap files")
    parser.add_argument("--dut1", required=True, help="DUT1 transmit pcap (reference send time)")
    parser.add_argument("--proxy1", required=True, help="Proxy1 receive pcap")
    parser.add_argument("--proxy2", required=True, help="Proxy2 transmit pcap")
    parser.add_argument("--dut2", required=True, help="DUT2 receive pcap")
    parser.add_argument("--dut1-dst", nargs="+", type=parse_address, metavar="ADDR",
                        help="Keep only DUT1 packets sent to these IP/MAC addresses (e.g. ff02::1)")
    parser.add_argument("--prox1-src", "--proxy1-src", dest="prox1_src", nargs="+", type=parse_address,
                        metavar="ADDR", help="Keep only proxy1 packets from these IP/MAC addresses")
    parser.add_argument("--dut2-src", nargs="+", type=parse_address, metavar="ADDR",
                        help="Keep only DUT2 packets from these IP/MAC addresses")
    parser.add_argument("--output", help="Output CSV path (default: <data-root>/latency_<dut1>.csv)")
    args = parser.parse_args()

    data_root = Path(args.data_root)
    paths = {s: data_root / getattr(args, s) for s in STAGES}
    for stage, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"--{stage} file not found: {path}")

    out_path = Path(args.output) if args.output else data_root / f"latency_{paths['dut1'].stem}.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dup_path = out_path.with_name(out_path.stem + "_duplicates.csv")

    print("Decoding pcaps...")
    filters = {"dut1": {"dst": args.dut1_dst}, "proxy1": {"src": args.prox1_src},
               "dut2": {"src": args.dut2_src}}
    stages = {s: load_stage(p, **filters.get(s, {})) for s, p in paths.items()}
    if not stages["dut1"]:
        raise ValueError(f"No signed BSMs found in {paths['dut1']}")

    rows = match(stages)
    write_csv(rows, out_path)
    n_dups = write_duplicates_csv(stages, dup_path)

    report_duplicates(stages)
    report_latency(rows)
    report_anomalies(rows, stages)
    print(f"\nWrote {len(rows)} rows to {out_path}")
    print(f"Wrote {n_dups} repeated DUT1 signatures to {dup_path}")
    for path in plot_latency(rows, data_root, out_path.stem):
        print(f"Wrote plot {path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
