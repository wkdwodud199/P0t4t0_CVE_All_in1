# CVE Scanner

**Web Application CVE Vulnerability Scanner**

Automatically detects web technologies and searches for known CVEs using the NIST National Vulnerability Database (NVD) API.

Created by **P0t4t0**

---

## Features

- ✅ **Automatic Technology Detection**: Identifies web servers, frameworks, CMS, libraries, and their versions
- ✅ **Real-time CVE Lookup**: Queries NIST NVD API for the latest vulnerability data
- ✅ **Metasploit Module Search**: Automatically searches for exploit modules in Metasploit Framework
- ✅ **Exploit Code Display**: Shows actual exploit code inline from Exploit-DB (first 50 lines)
- ✅ **Ready-to-use Commands**: Generates msfconsole commands for detected vulnerabilities
- ✅ **Severity-based Filtering**: Filter results by CRITICAL, HIGH, MEDIUM, or LOW severity
- ✅ **Multiple Export Formats**: Export results as JSON, CSV, or HTML reports
- ✅ **CVSS Scoring**: Displays CVSS scores and severity ratings
- ✅ **Version Matching**: Intelligently matches detected versions to affected CVE ranges

---

## Installation

### Install Dependencies

```bash
pip install -r requirements.txt
```

### (Optional) Get NVD API Key

For higher rate limits, get a free API key:
- Visit: https://nvd.nist.gov/developers/request-an-api-key
- Without key: 5 requests per 30 seconds
- With key: 50 requests per 30 seconds

---

## Usage

### Basic Scan

```bash
python cve_scanner.py -u https://example.com
```

### With NVD API Key (Recommended)

```bash
python cve_scanner.py -u https://example.com --api-key YOUR_API_KEY
```

### Filter by Severity

```bash
python cve_scanner.py -u https://target.com --severity HIGH
```

### Export Results

```bash
# JSON format
python cve_scanner.py -u https://example.com -o report.json --format json

# CSV format
python cve_scanner.py -u https://example.com -o report.csv --format csv

# HTML report
python cve_scanner.py -u https://example.com -o report.html --format html
```

### Technology Detection Only

```bash
python cve_scanner.py -u https://example.com --no-cve
```

### With Metasploit Module Search

```bash
python cve_scanner.py -u https://target.com --metasploit
```

This will:
- Search for Metasploit exploit modules for each detected CVE
- Retrieve actual exploit code from Exploit-DB
- Display the first 50 lines of each exploit inline in the terminal
- Provide ready-to-use msfconsole commands

---

## Examples

### Scan a WordPress Site

```bash
python cve_scanner.py -u https://wordpress-site.com --api-key YOUR_KEY
```

**Output:**
```
================================================================================
PHASE 1: TECHNOLOGY DETECTION
================================================================================
[*] Scanning: https://wordpress-site.com

[*] Analyzing HTTP headers...
  [+] Detected: Apache HTTP Server 2.4.41 (web-server)
  [+] Detected: PHP 7.4.3 (language)

[*] Analyzing HTML content...
  [+] Detected: WordPress 5.8 (cms)

[*] Detecting JavaScript libraries...
  [+] Detected: jQuery 3.5.1 (library)

================================================================================
PHASE 2: CVE VULNERABILITY SCANNING
================================================================================

[*] Searching CVEs for: WordPress 5.8
  [+] Found 23 CVEs
  [+] 23 CVEs match version 5.8

================================================================================
CVE VULNERABILITY REPORT
================================================================================

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL SEVERITY (3 CVEs)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CVE-2021-24499 - CVSS 9.8
   Published: 2021-09-09
   Product: WordPress
   Affected: 5.8
   Description: WordPress Core is vulnerable to SQL injection...
   References:
     - https://nvd.nist.gov/vuln/detail/CVE-2021-24499
     - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
```

---

## Project Structure

```
cve-scanner/
│
├── cve_scanner.py       # Main CLI application
├── tech_detector.py     # Technology detection module
├── cve_checker.py       # NVD API integration
├── msf_searcher.py      # Metasploit & Exploit-DB search module
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

---

## How It Works

### Phase 1: Technology Detection

The scanner analyzes multiple sources to identify technologies:

1. **HTTP Headers**: `Server`, `X-Powered-By`, `X-Generator`, etc.
2. **HTML Content**: Meta tags, script sources, link tags
3. **Common Files**: `readme.html`, `composer.json`, `package.json`
4. **Error Pages**: Server error messages revealing versions
5. **CMS Signatures**: WordPress, Joomla, Drupal specific files
6. **JavaScript Libraries**: jQuery, React, Vue.js detection

### Phase 2: CVE Vulnerability Scanning

For each detected technology with a known version:

1. **Query NVD API**: Search NIST database for CVEs
2. **Version Matching**: Filter CVEs by exact version or version ranges
3. **CVSS Scoring**: Extract severity ratings and scores
4. **Detailed Reports**: Show descriptions, references, and affected versions

---

## Detected Technologies

The scanner can identify:

### Web Servers
- Apache HTTP Server
- nginx
- Microsoft IIS
- LiteSpeed
- lighttpd

### Programming Languages
- PHP
- Python
- Ruby
- Node.js

### CMS Platforms
- WordPress
- Joomla
- Drupal
- Magento

### Frameworks
- Laravel
- Django
- Express
- ASP.NET
- React
- Vue.js
- Angular

### Libraries
- jQuery
- Bootstrap
- OpenSSL

---

## Output Formats

### JSON Export
```json
{
  "url": "https://example.com",
  "technologies": [
    {
      "name": "WordPress",
      "version": "5.8",
      "category": "cms"
    }
  ],
  "cves": [
    {
      "cve_id": "CVE-2021-24499",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "description": "..."
    }
  ],
  "stats": {
    "total_technologies": 4,
    "total_cves": 23,
    "critical": 3,
    "high": 8
  }
}
```

### HTML Report
Generates a professional HTML report with:
- Visual severity indicators
- Statistics dashboard
- Clickable CVE references
- Technology breakdown

---

## API Rate Limits

### Without API Key
- 5 requests per 30 seconds
- Scan may take longer for sites with multiple technologies

### With API Key
- 50 requests per 30 seconds
- Significantly faster scanning

---

## Limitations

1. **Technology Detection**: Can only detect technologies that leave fingerprints in HTTP responses
2. **Version Accuracy**: Some versions may be detected as ranges rather than exact numbers
3. **False Positives**: Generic technology names may match unrelated CVEs
4. **Rate Limits**: NVD API has rate limits (use API key for better performance)

---

## Troubleshooting

### "No technologies detected"
- Site may be behind a CDN/WAF that strips headers
- Try with `--no-cve` flag to see raw detection output

### "API rate limit exceeded"
- Get an NVD API key for higher limits
- Add delays between scans

### SSL Certificate Errors
- The scanner ignores SSL verification by default
- Some proxies may still cause issues

---

## Security & Ethical Use

⚠️ **Important**: This tool is for authorized security testing only.

- Only scan systems you own or have permission to test
- Respect rate limits and API terms of service
- Follow responsible disclosure for any vulnerabilities found

---

## Contributing

Found a bug or want to add features?
- Report issues
- Submit pull requests
- Suggest technology detection patterns

---

## License

Free to use for educational and authorized security testing purposes.

---

## Credits

- **NIST NVD**: CVE database and API
- **BeautifulSoup**: HTML parsing
- **Requests**: HTTP client

Created by **P0t4t0** 🥔

---

## Recent Updates

### v1.2.0 - Enhanced CVE Detection & Korean Translation (Latest)
- ✅ **대폭 향상된 CVE 탐지율**: 버전 매칭 알고리즘 개선으로 3개 → 108개 CVE 탐지 (36배 증가)
- ✅ **한국어 보안 용어 번역**: CVE 설명에서 주요 보안 용어 자동 한국어 변환
- ✅ **Exploit 우선 정렬**: Exploit이 있는 CVE를 각 심각도 그룹 내에서 최우선 표시
- ✅ **HTML 보고서에 전체 Exploit 코드 포함**: 클릭 가능한 접기/펼치기 형식으로 제공
- ✅ **개선된 버전 범위 매칭**: `<`, `>`, `<=`, `>=` 연산자 정확한 처리
- ✅ **메이저.마이너 버전 유연 매칭**: 패치 버전이 달라도 관련 CVE 탐지

### v1.1.0 - Exploit Code Display
- ✅ Added Exploit-DB integration via GitLab CSV database
- ✅ Automatic exploit code fetching and inline display
- ✅ Shows first 50 lines of actual exploit code
- ✅ Korean language support for all output messages
- ✅ Improved Windows console encoding handling

## Roadmap

Future enhancements:
- [ ] Local CVE database caching
- [ ] Plugin/theme detection for CMS platforms
- [ ] Network port scanning integration
- [ ] GUI version
- [ ] Multi-threaded scanning
- [ ] Docker support


