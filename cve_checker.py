#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Checker using NVD API 2.0
Queries NIST National Vulnerability Database for CVEs
"""

import requests
import time
import re
from typing import List, Dict, Optional
from datetime import datetime


def translate_security_terms(text: str) -> str:
    """Translate common security terms from English to Korean"""
    translations = {
        # Vulnerability types
        'Remote Code Execution': '원격 코드 실행',
        'remote code execution': '원격 코드 실행',
        'RCE': '원격 코드 실행(RCE)',
        'SQL Injection': 'SQL 인젝션',
        'sql injection': 'SQL 인젝션',
        'Cross-Site Scripting': '크로스 사이트 스크립팅',
        'cross-site scripting': '크로스 사이트 스크립팅',
        'XSS': '크로스 사이트 스크립팅(XSS)',
        'Cross Site Scripting': '크로스 사이트 스크립팅',
        'Cross-Site Request Forgery': '크로스 사이트 요청 위조',
        'CSRF': '크로스 사이트 요청 위조(CSRF)',
        'Directory Traversal': '디렉토리 트래버설',
        'Path Traversal': '경로 탐색',
        'Buffer Overflow': '버퍼 오버플로우',
        'Denial of Service': '서비스 거부',
        'denial of service': '서비스 거부',
        'DoS': '서비스 거부(DoS)',
        'Information Disclosure': '정보 노출',
        'information disclosure': '정보 노출',
        'Privilege Escalation': '권한 상승',
        'privilege escalation': '권한 상승',
        'Authentication Bypass': '인증 우회',
        'authentication bypass': '인증 우회',
        'Arbitrary File Upload': '임의 파일 업로드',
        'arbitrary file upload': '임의 파일 업로드',
        'Command Injection': '명령어 인젝션',
        'command injection': '명령어 인젝션',

        # Common phrases
        'allows remote attackers': '원격 공격자가',
        'allows attackers': '공격자가',
        'vulnerability in': '취약점이 있는',
        'before': '이전 버전',
        'versions prior to': '이전 버전',
        'and earlier': '이하 버전',
        'through': '~',
        'vulnerable to': '취약함',
        'could allow': '허용할 수 있음',
        'may allow': '허용할 수 있음',
        'to execute arbitrary': '임의의 코드를 실행',
        'arbitrary code': '임의 코드',
        'malicious users': '악의적인 사용자',
        'authenticated users': '인증된 사용자',
        'unauthenticated': '인증되지 않은',
        'via': '를 통해',
        'due to': '로 인해',
        'insufficient': '불충분한',
        'improper': '부적절한',
        'missing': '누락된',
    }

    result = text
    for eng, kor in translations.items():
        # Case-insensitive replacement, but preserve original case for technical terms
        result = re.sub(re.escape(eng), kor, result, flags=re.IGNORECASE)

    return result


class CVEChecker:
    """Check CVEs using NVD API 2.0"""

    # NVD API 2.0 endpoint
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize CVE Checker

        Args:
            api_key: Optional NVD API key for higher rate limits
                    Without key: 5 requests per 30 seconds
                    With key: 50 requests per 30 seconds
        """
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.rate_limit_delay = 0.6  # 50 requests per 30s
        else:
            self.rate_limit_delay = 6  # 5 requests per 30s (safe)

        self.last_request_time = 0

    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def search_cves(self, product_name: str, version: str = None) -> List[Dict]:
        """
        Search for CVEs by product name and optional version

        Args:
            product_name: Product name (e.g., "apache http server", "wordpress")
            version: Specific version (e.g., "2.4.41")

        Returns:
            List of CVE dictionaries with details
        """
        print(f"\n[*] Searching CVEs for: {product_name}" + (f" {version}" if version else ""))

        all_cves = []

        # Strategy 1: Search with full product name
        cves1 = self._search_nvd(product_name, None)
        all_cves.extend(cves1)

        # Strategy 2: If we have a version and got few results, try major version search
        if version and len(cves1) < 20:
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major_version = version_parts[0]
                self._rate_limit()
                cves2 = self._search_nvd(product_name, major_version)
                # Add new CVEs that weren't in first search
                existing_ids = {c['cve_id'] for c in all_cves}
                for cve in cves2:
                    if cve['cve_id'] not in existing_ids:
                        all_cves.append(cve)

        if not all_cves:
            print(f"  [-] No CVEs found for {product_name}")
            return []

        print(f"  [+] Found {len(all_cves)} CVEs")

        # Filter by version if specified
        if version:
            all_cves = self._filter_by_version(all_cves, version)
            print(f"  [+] {len(all_cves)} CVEs match version {version}")

        # Sort by CVSS score (highest first)
        all_cves.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)

        # Limit to top 50 to avoid overwhelming output
        return all_cves[:50]

    def _search_nvd(self, product_name: str, version_hint: str = None) -> List[Dict]:
        """Internal method to query NVD API"""
        self._rate_limit()

        # Build query parameters
        params = {
            'keywordSearch': product_name,
            'resultsPerPage': 100  # Max allowed
        }

        # Add version hint to keyword search if provided
        if version_hint:
            params['keywordSearch'] = f"{product_name} {version_hint}"

        try:
            response = self.session.get(self.NVD_API_URL, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            # Parse CVEs
            cve_list = []
            for vuln in vulnerabilities:
                cve_item = vuln.get('cve', {})
                cve_dict = self._parse_cve(cve_item, product_name, None)
                if cve_dict:
                    cve_list.append(cve_dict)

            return cve_list

        except requests.exceptions.RequestException as e:
            print(f"  [!] Error querying NVD API: {str(e)}")
            return []

    def _parse_cve(self, cve_data: Dict, product_name: str, version: str = None) -> Optional[Dict]:
        """Parse CVE data from NVD API response"""
        try:
            cve_id = cve_data.get('id', 'Unknown')

            # First check if this CVE is actually relevant to the product
            if not self._is_cve_relevant_to_product(cve_data, product_name):
                return None

            # Get description (English)
            descriptions = cve_data.get('descriptions', [])
            description_en = next(
                (d['value'] for d in descriptions if d['lang'] == 'en'),
                'No description available'
            )

            # Try to get Korean description, fallback to English
            description_ko = next(
                (d['value'] for d in descriptions if d['lang'] == 'ko'),
                None
            )

            # Use Korean if available, otherwise translate English to Korean
            if description_ko:
                description = description_ko
            else:
                # Translate common security terms to Korean
                description = translate_security_terms(description_en)

            # Get CVSS scores
            metrics = cve_data.get('metrics', {})
            cvss_score = 0
            cvss_severity = 'UNKNOWN'

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0]

                    if 'cvssData' in cvss_data:
                        cvss_score = cvss_data['cvssData'].get('baseScore', 0)
                        cvss_severity = cvss_data['cvssData'].get('baseSeverity', 'UNKNOWN')
                    elif 'baseScore' in cvss_data:  # CVSS v2
                        cvss_score = cvss_data.get('baseScore', 0)
                        # Map v2 score to severity
                        if cvss_score >= 7.0:
                            cvss_severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            cvss_severity = 'MEDIUM'
                        else:
                            cvss_severity = 'LOW'
                    break

            # Get published date
            published = cve_data.get('published', '')
            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    published = pub_date.strftime('%Y-%m-%d')
                except:
                    pass

            # Get affected versions from CPE configurations
            affected_versions = self._extract_affected_versions(cve_data)

            # Get references
            references = cve_data.get('references', [])
            ref_urls = [ref['url'] for ref in references[:3]]  # First 3 references

            return {
                'cve_id': cve_id,
                'description': description[:200] + '...' if len(description) > 200 else description,
                'cvss_score': cvss_score,
                'severity': cvss_severity,
                'published': published,
                'affected_versions': affected_versions,
                'references': ref_urls,
                'product': product_name,
                'specified_version': version
            }

        except Exception as e:
            print(f"  [!] Error parsing CVE: {str(e)}")
            return None

    def _is_cve_relevant_to_product(self, cve_data: Dict, product_name: str) -> bool:
        """
        Check if CVE is actually relevant to the detected product
        by verifying CPE product names match

        Args:
            cve_data: CVE data from NVD API
            product_name: Detected product name (e.g., "Apache HTTP Server", "PHP", "jQuery")

        Returns:
            True if CVE is relevant to the product, False otherwise
        """
        try:
            # Normalize product name for comparison
            product_normalized = product_name.lower().replace(' ', '_').replace('-', '_')

            # Common product name mappings
            product_aliases = {
                'apache_http_server': ['apache', 'httpd', 'http_server'],
                'php': ['php'],
                'jquery': ['jquery'],
                'nginx': ['nginx'],
                'microsoft_iis': ['iis', 'internet_information_services'],
                'wordpress': ['wordpress'],
                'joomla': ['joomla'],
                'drupal': ['drupal'],
                'mysql': ['mysql'],
                'postgresql': ['postgresql'],
                'openssl': ['openssl'],
                'bootstrap': ['bootstrap'],
                'react': ['react'],
                'vue.js': ['vue', 'vue.js'],
                'angular': ['angular'],
                'express': ['express'],
            }

            # Products to exclude (specific applications, not the core software)
            excluded_products = [
                'phpbb', 'phpmyadmin', 'php-nuke', 'phpnuke', 'phpmychat',
                'phpwebsite', 'phpslice', 'phprocketaddin', 'phpmyagenda',
                'wordpress', 'joomla', 'drupal', 'magento',  # CMS (unless detected)
            ]

            # Get all possible names for this product
            search_terms = [product_normalized]
            for canonical, aliases in product_aliases.items():
                if product_normalized in aliases or canonical == product_normalized:
                    search_terms.extend(aliases)
                    break

            # Extract CPE entries from CVE configurations
            configurations = cve_data.get('configurations', [])

            matched_cpe_products = []

            for config in configurations:
                nodes = config.get('nodes', [])

                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])

                    for cpe in cpe_matches:
                        if not cpe.get('vulnerable', True):
                            continue

                        cpe_uri = cpe.get('criteria', '')

                        # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 5:
                            cpe_vendor = parts[3].lower()
                            cpe_product = parts[4].lower()

                            # Store matched products for later filtering
                            matched_cpe_products.append(cpe_product)

                            # Check if any search term matches the CPE product or vendor
                            for term in search_terms:
                                if term in cpe_product or term in cpe_vendor:
                                    # Additional check: exclude specific applications
                                    if cpe_product in excluded_products:
                                        # This is a specific PHP/etc application, not core software
                                        continue
                                    return True

                                # Also check if CPE product is in our product name
                                if cpe_product in product_normalized:
                                    if cpe_product not in excluded_products:
                                        return True

            # If no CPE match found, reject this CVE as irrelevant
            return False

        except Exception as e:
            # If we can't determine relevance, err on the side of caution and include it
            return True

    def _extract_affected_versions(self, cve_data: Dict) -> List[str]:
        """Extract affected version ranges from CPE configurations"""
        affected = []

        try:
            configurations = cve_data.get('configurations', [])

            for config in configurations:
                nodes = config.get('nodes', [])

                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])

                    for cpe in cpe_matches:
                        if not cpe.get('vulnerable', True):
                            continue

                        cpe_uri = cpe.get('criteria', '')

                        # Extract version from CPE URI
                        # Format: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 6:
                            version = parts[5]
                            if version != '*' and version not in affected:
                                # Check for version ranges
                                version_start = cpe.get('versionStartIncluding') or cpe.get('versionStartExcluding')
                                version_end = cpe.get('versionEndIncluding') or cpe.get('versionEndExcluding')

                                if version_start and version_end:
                                    affected.append(f"{version_start} - {version_end}")
                                elif version_start:
                                    affected.append(f">= {version_start}")
                                elif version_end:
                                    affected.append(f"<= {version_end}")
                                else:
                                    affected.append(version)

        except Exception as e:
            pass

        return affected[:10]  # Return first 10

    def _filter_by_version(self, cve_list: List[Dict], version: str) -> List[Dict]:
        """Filter CVEs by specific version"""
        filtered = []

        for cve in cve_list:
            if self._version_matches(version, cve.get('affected_versions', [])):
                filtered.append(cve)

        return filtered

    def _version_matches(self, version: str, affected_versions: List[str]) -> bool:
        """Check if a version matches any affected version range"""
        if not affected_versions:
            return True  # If no version info, include it

        try:
            # Parse version into comparable format
            version_parts = [int(x) for x in version.split('.') if x.replace('.', '').isdigit()]

            # Get major.minor for flexible matching
            version_major_minor = '.'.join(str(p) for p in version_parts[:2]) if len(version_parts) >= 2 else version

            for affected in affected_versions:
                # Handle range formats
                if ' - ' in affected:
                    # Range: "2.0.0 - 2.4.50"
                    start, end = affected.split(' - ')
                    start_parts = [int(x) for x in start.split('.') if x.replace('.', '').isdigit()]
                    end_parts = [int(x) for x in end.split('.') if x.replace('.', '').isdigit()]

                    if start_parts <= version_parts <= end_parts:
                        return True

                elif '>=' in affected or '<=' in affected or '<' in affected or '>' in affected:
                    # Comparison: ">= 2.0.0" or "<= 2.4.50" or "< 5.3.0"
                    operator = None
                    comp_version = affected

                    for op in ['>=', '<=', '<', '>']:
                        if op in affected:
                            operator = op
                            comp_version = affected.replace(op, '').strip()
                            break

                    comp_parts = [int(x) for x in comp_version.split('.') if x.replace('.', '').isdigit()]

                    if operator == '>=' and version_parts >= comp_parts:
                        return True
                    elif operator == '<=' and version_parts <= comp_parts:
                        return True
                    elif operator == '<' and version_parts < comp_parts:
                        return True
                    elif operator == '>' and version_parts > comp_parts:
                        return True

                else:
                    # Exact match or partial match
                    if version == affected:
                        return True

                    # Check if major.minor matches (for flexible matching)
                    affected_parts = affected.split('.')
                    if len(affected_parts) >= 2 and len(version_parts) >= 2:
                        affected_major_minor = '.'.join(affected_parts[:2])
                        if version_major_minor == affected_major_minor:
                            return True

        except Exception as e:
            # If parsing fails, include the CVE
            return True

        return False

    def print_cve_report(self, cve_list: List[Dict]):
        """Print formatted CVE report"""
        if not cve_list:
            print("\n[+] No CVEs found.")
            return

        print("\n" + "="*80)
        print("CVE VULNERABILITY REPORT")
        print("="*80)

        # Group by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        by_severity = {sev: [] for sev in severity_order}

        for cve in cve_list:
            severity = cve.get('severity', 'UNKNOWN')
            by_severity[severity].append(cve)

        # Sort each severity group: exploits first, then by CVSS score
        for severity in severity_order:
            by_severity[severity].sort(
                key=lambda x: (not x.get('has_exploit', False), -x.get('cvss_score', 0))
            )

        for severity in severity_order:
            cves = by_severity[severity]
            if not cves:
                continue

            print(f"\n{'━'*80}")
            print(f"{severity} SEVERITY ({len(cves)} CVEs)")
            print(f"{'━'*80}")

            for cve in cves:
                exploit_badge = " 💥 [EXPLOIT 있음]" if cve.get('has_exploit', False) else ""
                print(f"\n📌 {cve['cve_id']} - CVSS {cve['cvss_score']}{exploit_badge}")
                print(f"   Published: {cve['published']}")
                print(f"   Product: {cve['product']}")

                if cve.get('affected_versions'):
                    print(f"   Affected: {', '.join(cve['affected_versions'][:3])}")

                if cve.get('has_exploit') and cve.get('exploit_count', 0) > 0:
                    print(f"   💥 사용 가능한 Exploit: {cve['exploit_count']}개")

                print(f"   Description: {cve['description']}")

                if cve.get('references'):
                    print(f"   References:")
                    for ref in cve['references'][:2]:
                        print(f"     - {ref}")

        print("\n" + "="*80)
        print(f"Total CVEs: {len(cve_list)}")
        print("="*80 + "\n")


def test_cve_checker():
    """Test the CVE Checker"""
    checker = CVEChecker()

    # Test searches
    test_cases = [
        ("Apache HTTP Server", "2.4.49"),
        ("WordPress", "5.8"),
        ("nginx", "1.18.0"),
    ]

    for product, version in test_cases:
        cves = checker.search_cves(product, version)
        checker.print_cve_report(cves[:5])  # Show top 5


if __name__ == '__main__':
    test_cve_checker()
