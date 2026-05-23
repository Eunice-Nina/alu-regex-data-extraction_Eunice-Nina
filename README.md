# ALU Regex Data Extraction & Secure Validation

A Python program that extracts and validates structured data from raw,
production-style text using regular expressions. Built with defensive
security thinking throughout.



## Project Structure


alu-regex-data-extraction/
├── input/
│   └── raw-text.txt        ← Realistic CRM-style log with messy data
├── src/
│   └── main.py             ← Extraction + validation logic
├── output/
│   └── sample-output.json  ← JSON results from the last run
└── README.md
```



## How to Run


```bash
# From the project root
python3 src/main.py
```

Output is printed to the console and saved to `output/sample-output.json`.



## Data Types Extracted (4 total)

| #  | Type            | Notes                                  |
|----|-----------------|----------------------------------------|
| 1  | Email addresses | With ALU domain classification         |
| 2  | Credit cards    | Visa, MC, AmEx, Discover + Luhn check  |
| 3  | URLs            | http/https only, phishing detection    |
| 4  | Phone numbers   | International format with country code |



## ALU Email Classification

All extracted emails are automatically categorised by domain:

| Category     | Domain                        |
|--------------|-------------------------------|
| ALU Official | `@alueducation.com`           |
| ALU Alumni   | `@alumni.alueducation.com`    |
| ALU SI       | `@si.alueducation.com`        |
| External     | Any other domain              |

The SI and Alumni checks run before the Official check to avoid the
`@alueducation.com` pattern matching subdomains incorrectly.



## Security Measures

1. **Hostile input scan first** — Before any extraction runs, the raw text
   is checked for XSS (`<script>`), SQL injection (`DROP TABLE`, `' OR '1'='1`),
   and JavaScript URL injection (`javascript:`). Lines containing these
   are stripped before processing continues.

2. **Credit card masking** — Full card numbers are never written to output.
   All results show only the last 4 digits: `**** **** **** 1234`.

3. **Luhn validation** — Every extracted card number is run through the
   standard Luhn checksum algorithm. Numbers that fail (including known
   dummy values like `0000-0000-0000-0000`) are flagged and rejected.

4. **Email masking** — Email local parts are partially masked in output
   (e.g. `jo***@example.com`) to limit exposure of personal data.

5. **URL safety** — Only `http://` and `https://` URLs are matched.
   `javascript:`, `data:`, and `ftp:` schemes are excluded by design.
   URLs are also checked against a list of known phishing keywords.



## Sample Output

```json
{
  "security_flags": [
    "HOSTILE INPUT DETECTED: XSS, SQL injection, or JS URL found..."
  ],
  "emails": [
    {
      "masked": "jo***@alumni.alueducation.com",
      "category": "ALU Alumni",
      "valid_alu_domain": true
    }
  ],
  "credit_cards": [
    {
      "masked": "**** **** **** 1111",
      "luhn_valid": true,
      "flagged": false,
      "note": "Passes Luhn check"
    },
    {
      "masked": "**** **** **** 0000",
      "luhn_valid": false,
      "flagged": true,
      "note": "Rejected — dummy/invalid card"
    }
  ],
  "urls": [
    {
      "url": "https://portal.alueducation.com/scholarships/renew",
      "suspicious": false,
      "note": "OK"
    },
    {
      "url": "http://totally-legit-alu.phishing.io/reset?admin=true",
      "suspicious": true,
      "note": "Blocked — possible phishing URL"
    }
  ],
  "phone_numbers": [
    "+250 788 123 456",
    "+49 30 1234 5678"
  ]
}
```
