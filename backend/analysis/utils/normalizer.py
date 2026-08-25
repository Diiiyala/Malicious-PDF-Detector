import re, base64, urllib.parse, logging
from analysis.utils.text_metrics import calculate_entropy

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYS = [ "eval", "exec", "cmd", "powershell",
        "http", "https", "script", "function",
        "fromcharcode", "atob", "document", "window"
    ]

ESCAPE_PATTERN = re.compile(
    r'\\u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})'
    r'|\\u([0-9a-fA-F]{4})'
    r'|\\x([0-9a-fA-F]{2})'
)

URL_LIKE_PATTERN = re.compile(r'(?:[a-zA-Z][a-zA-Z0-9+.-]*://|www\.)[^\s"\'<>()\[\]{}]+')

# -------------------------------------------------------------------------
# 1. Main Normalizer Entry Point
# -------------------------------------------------------------------------

def normalize_all(text, aggregator=None, max_rounds=3, max_size=2_000_000):

    if not text:
        return ""

    current = text
    seen_decoded = set()
    decoded_layers = []

    for _ in range(max_rounds):
        prev = current

        current = decode_pdf_hex_names(current)
        current = decode_unicode_escapes(current)
        current = decode_pdf_octal(current)
        current = normalize_js_brackets(current)
        current = normalize_join(current)
        current = normalize_string_concat(current)
        current = normalize_javascript_protocol(current)
        current = normalize_urls(current)
        current = decode_atob(current)
        
        current, new_layers = decode_staged_base64(current, seen_decoded)
        for layer in new_layers:
            decoded_layers.append(layer)
            if aggregator:
                aggregator.add_script(layer, "Normalization Layer", script_type="De-obfuscated Payload")

        current, new_layers = decode_generic_base64(current, seen_decoded)
        for layer in new_layers:
            decoded_layers.append(layer)
            if aggregator:
                aggregator.add_script(layer, "Normalization Layer", script_type="De-obfuscated Payload")

        if len(current) > max_size:
            current = current[:max_size]
            break
        
        if current == prev:
            break

    if decoded_layers:
        current += "\n--- ALL DECODED LAYERS ---\n" + "\n".join(decoded_layers)
    return current

# -------------------------------------------------------------------------
# 2. PDF Structure Normalization
# -------------------------------------------------------------------------

def decode_pdf_hex_names(text):

    def replace_hex(match):
        try:
            hex_val = match.group(1)
            return bytes.fromhex(hex_val).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug("PDF hex-name decode failed: %s", e)
            return match.group(0)

    return re.sub(r'#([0-9a-fA-F]{2})', replace_hex, text)


# -------------------------------------------------------------------------
# 3. JavaScript & Logic Normalization
# -------------------------------------------------------------------------

def normalize_js_brackets(text):
    
    text = re.sub(r'(\w+)\[["\']([^"\']+)["\']\]', r'\1.\2', text)
    text = re.sub(r'(\w+)\.(\w+)\[["\']([^"\']+)["\']\]', r'\1.\2.\3', text)
    return text

def extract_string_vars(text):

    var_map = {}
    pattern = r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']+)["\']'
    for m in re.finditer(pattern, text):
        var_map[m.group(1)] = m.group(2)
    return var_map

def replace_vars(text, var_map):

    if not var_map:
        return text
    def repl(match):
        l = var_map.get(match.group(1), match.group(1))
        r = var_map.get(match.group(2), match.group(2))
        return f'"{l}{r}"'
    return re.sub(r'\b(\w+)\s*\+\s*(\w+)\b', repl, text)

def normalize_string_concat(text):
    
    var_map = extract_string_vars(text)
    text = replace_vars(text, var_map)
    
    pattern = r'(["\'])([^"\']+)\1\s*\+\s*(["\'])([^"\']+)\3'
    while re.search(pattern, text):
        text = re.sub(pattern, lambda m: f'"{m.group(2)+m.group(4)}"', text)
    return text

def normalize_join(text):
    
    return re.sub(
        r'\[(.*?)\]\.join\(["\']?["\']?\)',
        lambda m: '"' + ''.join(re.findall(r'["\']([^"\']+)["\']', m.group(1))) + '"',
        text
    )

def normalize_javascript_protocol(text):

    def clean_js_uri(match):
        uri = match.group(0)
        return re.sub(r'[\t\n\r\s]', '', uri.lower())

    return re.sub(r'(?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:', clean_js_uri, text)


# -------------------------------------------------------------------------
# 4. Network & URL Normalization
# -------------------------------------------------------------------------

def normalize_urls(text):

    text = re.sub(r'\[\.\]', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\(\.\)', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'hxxp', 'http', text, flags=re.IGNORECASE)
    text = re.sub(r'h\*\*p', 'http', text, flags=re.IGNORECASE)
    text = re.sub(r'wxxs', 'wss', text, flags=re.IGNORECASE)
    text = re.sub(r'wxx', 'ws', text, flags=re.IGNORECASE)
    text = re.sub(r'(https?|ftp|smb|file|wss?)\s*:\s*/\s*/', r'\1://', text, flags=re.IGNORECASE)

    def unquote_url(match):
        try:
            return urllib.parse.unquote(match.group(0))
        except Exception as e:
            logger.debug("URL unquote failed: %s", e)
            return match.group(0)

    return URL_LIKE_PATTERN.sub(unquote_url, text)

# -------------------------------------------------------------------------
# 5. Decoding
# -------------------------------------------------------------------------

def decode_pdf_octal(text):
    
    if not text:
        return ""
        
    def replace_octal(match):
        try:
            octal_str = match.group(1)
            return chr(int(octal_str, 8))
        except (ValueError, TypeError):
            return match.group(0)

    return re.sub(r'\\([0-7]{2,3})', replace_octal, text)


def decode_unicode_escapes(text):

    def replace_escape(match):
        high, low, single, byte = match.groups()

        try:
            if high and low:
                code = 0x10000 + ((int(high, 16) - 0xD800) << 10) + (int(low, 16) - 0xDC00)
                return chr(code)

            digits = single or byte
            code = int(digits, 16)

            if 0xD800 <= code <= 0xDFFF:
                return match.group(0)

            return chr(code)

        except (ValueError, OverflowError):
            return match.group(0)

    return ESCAPE_PATTERN.sub(replace_escape, text)


def decode_atob(text):
    pattern = r'atob\(["\']([A-Za-z0-9+/=]+)["\']\)'

    def repl(m):
        try:
            return base64.b64decode(m.group(1)).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug("atob base64 decode failed: %s", e)
            return m.group(0)

    return re.sub(pattern, repl, text)

# -------------------------------------------------------------------------
# 6. Base64 Filters
# -------------------------------------------------------------------------

def is_valid_decoded(text):
    if not text or len(text) < 12:
        return False

    ascii_printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in "\t\n\r")
    if ascii_printable / len(text) < 0.85:
        return False

    if calculate_entropy(text) > 5.2:
        return False

    if any(k in text.lower() for k in SUSPICIOUS_KEYS) and len(text) > 15:
        return True

    return False

# 5.1 Staged Base64
def decode_staged_base64(text, seen):

    patterns = [
        r'util\.streamFromString\("([A-Za-z0-9+/=]+)"\)',
        r'util\.stringFromStream\(.*?"([A-Za-z0-9+/=]+)"\)',
        r'SOAP\.streamDecode\("([A-Za-z0-9+/=]+)"\)'
    ]

    new_parts = []

    for p in patterns:
        for m in re.finditer(p, text):
            b64 = m.group(1)

            if b64 in seen:
                continue

            try:
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')

                if is_valid_decoded(decoded):
                    seen.add(b64)
                    new_parts.append(decoded)

            except Exception as e:
                logger.debug("staged base64 decode failed: %s", e)
                continue

    return text, new_parts

# 5.2 Generic Base64
def decode_generic_base64(text, seen):

    matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
    new_parts = []

    for m in matches:
        if m in seen:
            continue

        try:
            decoded = base64.b64decode(m).decode('utf-8', errors='ignore')

            if is_valid_decoded(decoded):
                seen.add(m)
                new_parts.append(decoded)

        except Exception as e:
            logger.debug("generic base64 decode failed: %s", e)
            continue

    return text, new_parts