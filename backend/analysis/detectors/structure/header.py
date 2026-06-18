import re
from analysis.utils.models import Threat


def analyze_header(raw_data) -> list[Threat]:
    threats = []
    try:
        # Check for PDF Signature
        header_index = raw_data.find(b"%PDF-")

        if header_index == -1:
            header_display = "".join([chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in raw_data[:10]])
            threats.append(Threat(
                id="STR-HDR-MALFORMED", category="Structure", severity=10,
                description=f"Malformed PDF header (Found: '{header_display}' instead of %PDF- signature)", location="Header"
            ))

        # Check for Signature Offset
        elif header_index > 0:
            threats.append(Threat(
                id="STR-HDR-OFFSET", category="Structure", severity=7,
                description=f"PDF signature is not at the start (Offset: {header_index} bytes - potential hiding)", location="Header"
            ))

        # Validate PDF Version presence
        if header_index != -1:
            version_area = raw_data[header_index+5 : header_index+15]
            version_match = re.search(b"^[0-9.]+", version_area)

            if not version_match:
                threats.append(Threat(
                    id="STR-HDR-NOVER", category="Structure", severity=7,
                    description="PDF version missing or malformed in header", location="Header"
                ))

        # Check for Multiple Headers
        header_count = raw_data.count(b"%PDF-")
        if header_count > 1:
            threats.append(Threat(
                id="STR-HDR-MULTI", category="Structure", severity=8,
                description=f"Multiple PDF headers detected ({header_count} found - potential spoofing)", location="Header"
            ))

    except Exception:
        pass

    return threats
