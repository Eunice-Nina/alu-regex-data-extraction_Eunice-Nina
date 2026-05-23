"""
ALU Regex Data Extraction & Secure Validation

 Extractions made from raw text input:
  1. Email addresses     
  2. Credit card numbers 
  3. URLs               
  4. Phone numbers      

Security: Flags hostile input, masks sensitive data,
          rejects suspicious patterns before processing.
"""

import re
import json
import os


# SECURITY: Patterns that indicate hostile input

HOSTILE_PATTERNS = [
    r"<script[\s\S]*?>[\s\S]*?</script>",   # XSS script injection
    r"javascript\s*:",                        # JS protocol in URLs
    r"(DROP|DELETE|INSERT|UPDATE)\s+TABLE",  # SQL DDL/DML injection
    r"'\s*OR\s*'1'\s*=\s*'1",               # Classic SQL boolean bypass
    r";\s*--",                               # SQL comment terminator
]

def is_hostile(text):
    """
    Scan raw text for known hostile/malicious patterns.
    Returns True if any suspicious content is detected.
    Security note: never trust raw input from external APIs.
    """
    for pattern in HOSTILE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False



# MASKING HELPERS (sensitive data protection)


def mask_card(card_number):
    """
    Mask credit card for safe output — only show last 4 digits.
    Security note: full card numbers must never appear in logs or output.
    e.g. 4111-1111-1111-1111 → **** **** **** 1111
    """
    digits = re.sub(r"\D", "", card_number)
    return "**** **** **** " + digits[-4:] if len(digits) >= 4 else "****"

def mask_email(email):
    """
    Partially mask email local part to reduce personal data exposure.
    e.g. john.mugisha@alumni.alueducation.com → jo***@alumni.alueducation.com
    """
    local, domain = email.rsplit("@", 1)
    masked_local = local[:2] + "***" if len(local) > 2 else "***"
    return f"{masked_local}@{domain}"



# REGEX PATTERNS


# 1.EMAILS 
# Matches standard email format: local@domain.tld
# Local part: starts with alphanumeric, allows dots/underscores/hyphens
# Domain: at least one dot, TLD of 2+ letters
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9][\w.\-]*@[a-zA-Z0-9][\w.\-]*\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

# ALU-specific domain validators (order matters — most specific first)
ALU_SI      = re.compile(r"[\w.\-]+@si\.alueducation\.com$",      re.IGNORECASE)
ALU_ALUMNI  = re.compile(r"[\w.\-]+@alumni\.alueducation\.com$",  re.IGNORECASE)
ALU_OFFICIAL= re.compile(r"[\w.\-]+@alueducation\.com$",          re.IGNORECASE)

def classify_email(email):
    """
    Return the ALU category of an email address.
    Check SI and Alumni before Official to avoid prefix mis-matching.
    """
    if ALU_SI.match(email):
        return "ALU SI"
    if ALU_ALUMNI.match(email):
        return "ALU Alumni"
    if ALU_OFFICIAL.match(email):
        return "ALU Official"
    return "External"


# 2.CREDIT CARDS 
# Covers three real-world formats:
#   • Visa/Mastercard: 4 groups of 4 digits separated by space or hyphen
#   • AmEx:            4-6-5 digit groups  (15 digits total)
#   • Discover/plain:  16 consecutive digits with no separator
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}"  # Visa/MC: 4-4-4-4
    r"|\d{4}[\s\-]\d{6}[\s\-]\d{5}"                   # AmEx:    4-6-5
    r"|\d{16})\b"                                       # Discover: 16 raw digits
)

# Cards that are obviously invalid test values
INVALID_CARDS = {"0000000000000000"}

def luhn_check(number):
    """
    Luhn algorithm — the standard checksum used by card networks to
    catch typos and reject obviously fake numbers.
    Returns True only if the number passes the checksum.
    """
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# 3.URLs 
# Only accepts http:// or https:// — blocks javascript:, ftp:, data:
# Stops at whitespace or unsafe characters ( " ' < > )
URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

# Keywords that signal phishing or attacker-controlled domains
SUSPICIOUS_URL_KEYWORDS = ["phishing", "attacker", "totally-legit", "reset?admin=true"]

def is_suspicious_url(url):
    """Flag URLs that contain known phishing or injection indicators."""
    return any(kw in url.lower() for kw in SUSPICIOUS_URL_KEYWORDS)


# 4.PHONE NUMBERS 
# International format starting with + and country code
# Allows digits, spaces, and hyphens as separators
# Length: 8–18 characters after the + (covers most international numbers)
# Examples: +250 788 123 456 | +49 30 1234 5678 | +250-789-000-111
PHONE_PATTERN = re.compile(
    r"\+\d[\d\s\-]{7,17}\d"
)



# MAIN EXTRACTION FUNCTION


def extract_all(text):
    results = {
        "security_flags": [],
        "emails": [],
        "urls": [],
        "phone_numbers": [],
        "credit_cards": [],
    }

    # ── Security scan runs FIRST, before any extraction ──
    if is_hostile(text):
        results["security_flags"].append(
            "HOSTILE INPUT DETECTED: XSS, SQL injection, or JS URL found. "
            "Suspicious lines were stripped before extraction."
        )
        # Remove only the lines that contain hostile content
        clean_lines = [line for line in text.splitlines() if not is_hostile(line)]
        text = "\n".join(clean_lines)
    else:
        results["security_flags"].append("No hostile patterns detected.")

    # 1. Emails 
    raw_emails = EMAIL_PATTERN.findall(text)
    seen_emails = set()
    for email in raw_emails:
        key = email.lower()
        if key in seen_emails:
            continue
        seen_emails.add(key)
        category = classify_email(email)
        results["emails"].append({
            "masked":          mask_email(email),
            "category":        category,
            "valid_alu_domain": category != "External"
        })

    # 2. Credit Cards 
    raw_cards = CREDIT_CARD_PATTERN.findall(text)
    seen_cards = set()
    for card in raw_cards:
        digits = re.sub(r"\D", "", card)
        if digits in seen_cards:
            continue
        seen_cards.add(digits)

        is_dummy      = digits in INVALID_CARDS
        passes_luhn   = luhn_check(digits) if not is_dummy else False
        flagged       = is_dummy or not passes_luhn

        results["credit_cards"].append({
            "masked":     mask_card(card),
            "luhn_valid": passes_luhn,
            "flagged":    flagged,
            "note":       "Rejected — dummy/invalid card" if flagged else "Passes Luhn check"
        })

    # 3. URLs
    raw_urls = URL_PATTERN.findall(text)
    for url in raw_urls:
        suspicious = is_suspicious_url(url)
        results["urls"].append({
            "url":        url,
            "suspicious": suspicious,
            "note":       "Blocked — possible phishing URL" if suspicious else "OK"
        })

    # 4. Phone Numbers
    raw_phones = PHONE_PATTERN.findall(text)
    results["phone_numbers"] = list(set(p.strip() for p in raw_phones))

    return results



# ENTRY POINT


if __name__ == "__main__":
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path  = os.path.join(base_dir, "input",  "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    print("Reading input file...")
    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    print("Running extraction and validation...\n")
    output = extract_all(raw_text)

    # Save JSON output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # Console summary
    print("  EXTRACTION SUMMARY")
    for flag in output["security_flags"]:
        print(f"  [SECURITY] {flag}")
    print(f"  Emails found    : {len(output['emails'])}")
    print(f"  Credit cards    : {len(output['credit_cards'])}")
    print(f"  URLs found      : {len(output['urls'])}")
    print(f"  Phone numbers   : {len(output['phone_numbers'])}")
    print(f"\nFull output saved to: {output_path}")
