import re
import logging

from analysis.utils.models import Threat
from analysis.detectors.structure.collector import ThreatCollector
from analysis.utils.normalizer import decode_pdf_octal, decode_pdf_hex_names

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Limits (defensive: raw scanning runs on attacker-controlled bytes)
# --------------------------------------------------------------------------
MAX_DICTS = 100000
MAX_DICT_SPAN = 65536
MAX_DEPTH = 12
MAX_REPORTED_VALUES = 4
MAX_VALUE_CHARS = 90
MAX_CONFLICT_TARGETS = 3
WS = b"\x00\t\n\x0c\r "
DELIMS = b"()<>[]{}/%"

ACTION_DUP_KEYS = {
    "/A", "/AA", "/OpenAction", "/URI", "/JS", "/JavaScript", "/F",
    "/Dest", "/Launch", "/Names", "/EmbeddedFile", "/S", "/Filter",
}

OCTAL_ESCAPE = re.compile(rb"\\[0-7]{2,3}")
HEX_ESCAPE = re.compile(rb"#[0-9A-Fa-f]{2}")


# ==========================================================================
# Minimal raw PDF syntax walker
# ==========================================================================

def _skip_ws(data: bytes, i: int, end: int) -> int:
    while i < end:
        c = data[i]
        if c in WS:
            i += 1
        elif c == 0x25:  # '%' comment runs to end of line
            while i < end and data[i] not in b"\r\n":
                i += 1
        else:
            break
    return i


def _read_name(data: bytes, i: int, end: int):
    j = i + 1
    while j < end and data[j] not in WS and data[j] not in DELIMS:
        j += 1
    return data[i:j].decode("latin-1"), j


def _skip_literal_string(data: bytes, i: int, end: int) -> int:
    depth = 0
    while i < end:
        c = data[i]
        if c == 0x5C:          # backslash escape
            i += 2
            continue
        if c == 0x28:          # (
            depth += 1
        elif c == 0x29:        # )
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return end


def _skip_value(data: bytes, i: int, end: int, depth: int, found: list, budget: list) -> int:
    i = _skip_ws(data, i, end)
    if i >= end:
        return end

    if data[i:i + 2] == b"<<":
        return _parse_dict(data, i, end, depth + 1, found, budget)

    c = data[i]

    if c == 0x3C:              # '<' hex string
        j = data.find(b">", i, end)
        return end if j < 0 else j + 1

    if c == 0x28:              # '(' literal string
        return _skip_literal_string(data, i, end)

    if c == 0x5B:              # '[' array
        j = i + 1
        while j < end:
            j = _skip_ws(data, j, end)
            if j < end and data[j] == 0x5D:
                return j + 1
            nj = _skip_value(data, j, end, depth + 1, found, budget)
            if nj <= j:
                return j + 1
            j = nj
        return end

    if c == 0x2F:              # '/' name
        _, j = _read_name(data, i, end)
        return j

    # bare token: number, keyword, or an "N G R" indirect reference
    j = i
    while j < end and data[j] not in WS and data[j] not in DELIMS:
        j += 1
    if j == i:
        return i + 1

    if data[i:j].isdigit():
        k = _skip_ws(data, j, end)
        k2 = k
        while k2 < end and data[k2] not in WS and data[k2] not in DELIMS:
            k2 += 1
        if k2 > k and data[k:k2].isdigit():
            k3 = _skip_ws(data, k2, end)
            if data[k3:k3 + 1] == b"R":
                return k3 + 1
    return j


def _parse_dict(data: bytes, i: int, end: int, depth: int, found: list, budget: list) -> int:
    budget[0] -= 1
    if budget[0] <= 0 or depth > MAX_DEPTH:
        return min(end, i + 2)

    start = i
    i += 2
    entries = []

    while i < end:
        i = _skip_ws(data, i, end)
        if i >= end:
            break
        if data[i:i + 2] == b">>":
            i += 2
            break

        if data[i] != 0x2F:                      # junk / malformed entry
            ni = _skip_value(data, i, end, depth, found, budget)
            i = ni if ni > i else i + 1
            continue

        key, i = _read_name(data, i, end)
        i = _skip_ws(data, i, end)
        value_start = i
        ni = _skip_value(data, i, end, depth, found, budget)
        i = ni if ni > i else i + 1
        entries.append((key, data[value_start:i]))

    grouped = {}
    for key, value in entries:
        grouped.setdefault(key, []).append(value)

    for key, values in grouped.items():
        if len(values) > 1:
            found.append((start, key, values))

    return i


def _stream_ranges(data: bytes):
    ranges = []
    for m in re.finditer(rb"\bstream\r?\n", data):
        stop = data.find(b"endstream", m.end())
        ranges.append((m.end(), stop if stop >= 0 else len(data)))
    return ranges


def scan_duplicate_keys(data: bytes) -> list:
    """Return [(offset, key, [raw_value, ...]), ...] for every dictionary
    that defines the same key more than once."""

    found = []
    if not data:
        return found

    budget = [MAX_DICTS]
    skip = _stream_ranges(data)
    skip_idx = 0
    pos = 0
    n = len(data)

    while pos < n and budget[0] > 0:
        idx = data.find(b"<<", pos)
        if idx < 0:
            break

        while skip_idx < len(skip) and skip[skip_idx][1] <= idx:
            skip_idx += 1
        if skip_idx < len(skip) and skip[skip_idx][0] <= idx < skip[skip_idx][1]:
            pos = skip[skip_idx][1]
            continue

        try:
            nxt = _parse_dict(data, idx, min(n, idx + MAX_DICT_SPAN), 0, found, budget)
        except Exception as e:
            logger.debug("Raw dictionary walk failed at offset %d: %s", idx, e)
            nxt = idx + 2

        pos = max(nxt, idx + 2)

    return found


# ==========================================================================
# Value summarising
# ==========================================================================

def _decode_literal(raw: bytes):
    m = re.search(rb"\(", raw)
    if m:
        text = _skip_literal_string(raw, m.start(), len(raw))
        value = raw[m.start() + 1:max(text - 1, m.start() + 1)]
        decoded = value.decode("utf-8", errors="ignore")
        decoded = decode_pdf_hex_names(decode_pdf_octal(decoded))
        for esc, char in (("\\(", "("), ("\\)", ")"), ("\\\\", "\\")):
            decoded = decoded.replace(esc, char)
        return decoded, raw
    m = re.search(rb"<([0-9A-Fa-f]+)>", raw)
    if m:
        try:
            return bytes.fromhex(m.group(1).decode()).decode("utf-8", errors="ignore"), raw
        except Exception:
            return None, raw
    return None, raw


def _summarize_value(raw: bytes) -> str:
    raw = raw.strip()

    if raw[:1] == b"(" or (raw[:1] == b"<" and raw[:2] != b"<<"):
        decoded, _ = _decode_literal(raw)
        if decoded is not None:
            text = decoded.strip()
            if len(text) > MAX_VALUE_CHARS:
                text = text[:MAX_VALUE_CHARS] + "..."
            return text or "(empty)"

    for marker, label in ((rb"/URI", "URI"), (rb"/JS", "JS"), (rb"/F", "File")):
        m = re.search(marker + rb"\s*[\(<]", raw)
        if m:
            decoded, _ = _decode_literal(raw[m.end() - 1:])
            if decoded:
                text = decoded.strip()
                if len(text) > MAX_VALUE_CHARS:
                    text = text[:MAX_VALUE_CHARS] + "..."
                return f"{label}: {text}"

    text = re.sub(rb"\s+", b" ", raw).decode("latin-1").strip()
    if len(text) > MAX_VALUE_CHARS:
        text = text[:MAX_VALUE_CHARS] + "..."
    return text or "(empty)"


def _is_obfuscated(raw: bytes) -> bool:
    return bool(OCTAL_ESCAPE.search(raw) or HEX_ESCAPE.search(raw))


# ==========================================================================
# Hex-escaped name objects  (/#4c#61u#6ech  ==  /Launch)
# ==========================================================================

NAME_TOKEN = re.compile(rb"/[^\s/\[\]<>(){}%]*#[0-9A-Fa-f]{2}[^\s/\[\]<>(){}%]*")
NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")

MAX_NAME_SCANS = 5000

DANGEROUS_NAMES = {
    "/launch": 12, "/javascript": 12, "/js": 12, "/openaction": 12,
    "/aa": 11, "/embeddedfile": 11, "/embeddedfiles": 11, "/gotor": 11,
    "/gotoe": 11, "/submitform": 11, "/importdata": 11, "/richmedia": 11,
    "/xfa": 11, "/uri": 10, "/acroform": 9, "/objstm": 9, "/filespec": 8,
}


def _decode_name(token: bytes) -> bytes:
    out = bytearray(token[:1])
    i = 1
    while i < len(token):
        if token[i] == 0x23 and i + 2 < len(token):
            chunk = token[i + 1:i + 3]
            try:
                out.append(int(chunk, 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(token[i])
        i += 1
    return bytes(out)


def decode_name_escapes(data: bytes) -> bytes:

    if not data or b"#" not in data:
        return data
    return NAME_TOKEN.sub(lambda m: _decode_name(m.group(0)), data)


def scan_name_obfuscation(raw_binary: bytes) -> list:
    records = []

    if not raw_binary or b"#" not in raw_binary:
        return records

    skip = _stream_ranges(raw_binary)
    scanned = 0

    for match in NAME_TOKEN.finditer(raw_binary):
        scanned += 1
        if scanned > MAX_NAME_SCANS:
            logger.debug("Name obfuscation scan hit its cap")
            break

        start = match.start()
        if any(lo <= start < hi for lo, hi in skip):
            continue

        token = match.group(0)
        escaped = [int(h, 16) for h in NAME_ESCAPE.findall(token)]
        if not escaped or not all(chr(c).isalnum() for c in escaped):
            continue

        decoded = _decode_name(token).decode("latin-1")

        records.append({
            "decoded": decoded,
            "written": token.decode("latin-1"),
            "severity": DANGEROUS_NAMES.get(decoded.lower(), 0),
            "location": f"Offset 0x{start:x}",
        })

    return records


def name_obfuscation_index(records: list) -> dict:

    index = {}
    for r in records:
        if r["severity"]:
            index.setdefault(r["decoded"].lower(), (r["written"], r["severity"]))
    return index


def build_name_obfuscation_threats(records: list, merged: set = None) -> list:

    collector = ThreatCollector("Structure")
    merged = merged or set()

    for r in records:
        if r["decoded"].lower() in merged:
            continue

        if r["severity"]:
            collector.add(
                "STR-EVASION-NAME", r["severity"],
                f"Obfuscated name object hides ({r['decoded']}) - written as ({r['written']}) "
                f"to defeat signature matching",
                r["location"],
            )
        else:
            collector.add(
                "STR-EVASION-NAME-GENERIC", 6,
                f"Name object written with unnecessary hex escapes "
                f"({r['written']} resolves to {r['decoded']})",
                r["location"],
            )

    return collector.render()


# ==========================================================================
# Public detector
# ==========================================================================

def analyze_dict_evasion(raw_binary: bytes):

    collector = ThreatCollector("Structure")
    conflicting_targets = []

    if not raw_binary:
        return [], []

    try:
        duplicates = scan_duplicate_keys(raw_binary)
    except Exception as e:
        logger.debug("Duplicate key scan failed: %s", e)
        return [], []

    for offset, key, values in duplicates:
        location = f"Offset 0x{offset:x}"
        summaries = []
        for raw in values:
            summary = _summarize_value(raw)
            if summary not in summaries:
                summaries.append(summary)

        shown = summaries[:MAX_REPORTED_VALUES]
        remaining = len(summaries) - len(shown)
        rendered = " | ".join(shown) + (f", +{remaining} more" if remaining else "")

        is_action_key = key in ACTION_DUP_KEYS
        conflicting = len(summaries) > 1
        obfuscated = any(_is_obfuscated(v) for v in values)

        if conflicting and is_action_key:
            encoding_note = (
                " - the hidden value uses escaped encoding to evade string matching"
                if obfuscated else ""
            )
            collector.add(
                "STR-EVASION-DUPKEY", 12,
                f"Parser confusion: duplicate key ({key}) with conflicting values "
                f"- readers may follow different targets{encoding_note} [{rendered}]",
                location,
            )
            for summary in shown:
                if summary.startswith(("URI:", "File:")) and summary not in conflicting_targets:
                    conflicting_targets.append(summary.split(": ", 1)[1])

        elif conflicting:
            collector.add(
                "STR-EVASION-DUPKEY-DATA", 7,
                f"Duplicate key ({key}) with conflicting values [{rendered}]",
                location,
            )

        elif is_action_key:
            collector.add(
                "STR-EVASION-DUPKEY-REPEAT", 8,
                f"Duplicate action key ({key}) defined {len(values)} times in one dictionary",
                location,
            )

    threats: list[Threat] = collector.render()
    return threats, conflicting_targets[:MAX_CONFLICT_TARGETS]
