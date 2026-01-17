#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Scanner - Web Application CVE Vulnerability Scanner
Detects technologies and searches for known CVEs
Created by P0t4t0
"""

import argparse
import sys
import os

# Fix Windows console encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from tech_detector import TechDetector
from cve_checker import CVEChecker
from msf_searcher import MetasploitSearcher
from typing import List, Dict


class CVEScanner:
    """Main CVE Scanner application"""

    def __init__(self, nvd_api_key: str = None, search_metasploit: bool = False):
        """
        Initialize CVE Scanner

        Args:
            nvd_api_key: Optional NVD API key for higher rate limits
            search_metasploit: Whether to search for Metasploit modules
        """
        self.tech_detector = TechDetector()
        self.cve_checker = CVEChecker(api_key=nvd_api_key)
        self.msf_searcher = MetasploitSearcher() if search_metasploit else None
        self.search_metasploit = search_metasploit

    def scan_url(self, url: str, check_cves: bool = True, severity_filter: str = None) -> Dict:
        """
        Scan a URL for technologies and CVEs

        Args:
            url: Target URL to scan
            check_cves: Whether to check for CVEs (default: True)
            severity_filter: Filter CVEs by severity (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            Dictionary with scan results
        """
        print(f"\n{'='*80}")
        print(f"CVE SCANNER - Web Application Vulnerability Scanner")
        print(f"{'='*80}\n")

        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        print(f"Target: {url}\n")

        # Step 1: Detect Technologies
        print("="*80)
        print("PHASE 1: TECHNOLOGY DETECTION")
        print("="*80)

        technologies = self.tech_detector.scan(url)
        self.tech_detector.print_summary()

        if not technologies:
            print("\n[!] No technologies detected. Cannot proceed with CVE scanning.")
            return {'technologies': [], 'cves': []}

        # Step 2: Check CVEs
        all_cves = []

        if check_cves:
            print("\n" + "="*80)
            print("PHASE 2: CVE VULNERABILITY SCANNING")
            print("="*80)

            for tech in technologies:
                name = tech['name']
                version = tech['version']

                # Skip if no version detected
                if version == 'unknown':
                    print(f"\n[~] Skipping {name} (version unknown)")
                    continue

                # Search CVEs
                cves = self.cve_checker.search_cves(name, version)

                # Apply severity filter if specified
                if severity_filter:
                    cves = [cve for cve in cves if cve['severity'] == severity_filter.upper()]

                all_cves.extend(cves)

            # Print CVE Report
            if all_cves:
                self.cve_checker.print_cve_report(all_cves)
            else:
                print("\n[+] No CVEs found for detected technologies!")
                print("="*80 + "\n")

        # Step 3: Search Metasploit modules (if enabled)
        all_msf_modules = []
        cve_exploit_map = {}  # CVE ID -> list of exploits

        if self.search_metasploit and all_cves:
            print("\n" + "="*80)
            print("PHASE 3: METASPLOIT MODULE SEARCH")
            print("="*80)

            # Search for each CVE
            searched_cves = set()
            for cve in all_cves[:10]:  # Limit to top 10 CVEs to avoid rate limits
                cve_id = cve['cve_id']
                if cve_id not in searched_cves:
                    modules = self.msf_searcher.search_by_cve(cve_id)
                    if modules:
                        for module in modules:
                            module['related_cve'] = cve_id
                        all_msf_modules.extend(modules)
                        cve_exploit_map[cve_id] = modules
                    searched_cves.add(cve_id)

            # Add exploit info to CVEs
            for cve in all_cves:
                if cve['cve_id'] in cve_exploit_map:
                    cve['has_exploit'] = True
                    cve['exploit_count'] = len(cve_exploit_map[cve['cve_id']])
                else:
                    cve['has_exploit'] = False
                    cve['exploit_count'] = 0

            # Print Metasploit modules
            if all_msf_modules:
                self.msf_searcher.print_module_report(all_msf_modules)

                # Generate ready-to-use commands
                commands = self.msf_searcher.generate_msf_commands(all_msf_modules)
                if commands:
                    print("\n" + "="*80)
                    print("READY-TO-USE METASPLOIT COMMANDS")
                    print("="*80)
                    for idx, cmd_info in enumerate(commands[:5], 1):  # Show top 5
                        print(f"\n[{idx}] {cmd_info['description']}")
                        print(f"    msfconsole -x 'use {cmd_info['module']}'")
                    print("\n" + "="*80 + "\n")
            else:
                print("\n[-] No Metasploit modules found for detected CVEs")
                print("="*80 + "\n")

        # Generate summary
        results = {
            'url': url,
            'technologies': technologies,
            'cves': all_cves,
            'metasploit_modules': all_msf_modules,
            'stats': {
                'total_technologies': len(technologies),
                'total_cves': len(all_cves),
                'total_msf_modules': len(all_msf_modules),
                'critical': len([c for c in all_cves if c['severity'] == 'CRITICAL']),
                'high': len([c for c in all_cves if c['severity'] == 'HIGH']),
                'medium': len([c for c in all_cves if c['severity'] == 'MEDIUM']),
                'low': len([c for c in all_cves if c['severity'] == 'LOW']),
            }
        }

        self._print_final_summary(results)

        return results

    def _print_final_summary(self, results: Dict):
        """Print final scan summary"""
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)

        stats = results['stats']

        print(f"\nTarget URL: {results['url']}")
        print(f"Technologies Detected: {stats['total_technologies']}")
        print(f"Total CVEs Found: {stats['total_cves']}")

        if stats.get('total_msf_modules', 0) > 0:
            print(f"Metasploit Modules Found: {stats['total_msf_modules']}")

        if stats['total_cves'] > 0:
            print(f"\nCVE Breakdown:")
            print(f"  🔴 CRITICAL: {stats['critical']}")
            print(f"  🟠 HIGH:     {stats['high']}")
            print(f"  🟡 MEDIUM:   {stats['medium']}")
            print(f"  🟢 LOW:      {stats['low']}")

            # Risk assessment
            if stats['critical'] > 0:
                print(f"\n⚠️  RISK LEVEL: CRITICAL - Immediate action required!")
            elif stats['high'] > 0:
                print(f"\n⚠️  RISK LEVEL: HIGH - Patch as soon as possible")
            elif stats['medium'] > 0:
                print(f"\n⚠️  RISK LEVEL: MEDIUM - Schedule updates")
            else:
                print(f"\n✅ RISK LEVEL: LOW - Continue monitoring")

        print("\n" + "="*80 + "\n")

    def export_results(self, results: Dict, output_file: str, format: str = 'json'):
        """
        Export scan results to file

        Args:
            results: Scan results dictionary
            output_file: Output file path
            format: Export format (json, csv, html)
        """
        # For HTML reports with exploits, fetch full exploit code
        if format == 'html' and self.search_metasploit and results.get('metasploit_modules'):
            print("\n[*] HTML 보고서용 전체 exploit 코드 다운로드 중...")
            for module in results['metasploit_modules']:
                if 'edb_id' in module and not module.get('exploit_code_full'):
                    edb_id = module['edb_id']
                    full_code = self.msf_searcher._fetch_exploit_code(edb_id, full_code=True)
                    if full_code:
                        module['exploit_code_full'] = full_code
                        print(f"  [+] Exploit-DB {edb_id} 전체 코드 다운로드 완료")

        if format == 'json':
            self._export_json(results, output_file)
        elif format == 'csv':
            self._export_csv(results, output_file)
        elif format == 'html':
            self._export_html(results, output_file)
        else:
            print(f"[!] Unsupported format: {format}")

    def _export_json(self, results: Dict, output_file: str):
        """Export results as JSON"""
        import json

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"[+] Results exported to: {output_file}")

    def _export_csv(self, results: Dict, output_file: str):
        """Export CVEs as CSV"""
        import csv

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['CVE ID', 'Product', 'Version', 'CVSS Score', 'Severity', 'Published', 'Description'])

            for cve in results['cves']:
                writer.writerow([
                    cve['cve_id'],
                    cve['product'],
                    cve.get('specified_version', ''),
                    cve['cvss_score'],
                    cve['severity'],
                    cve['published'],
                    cve['description']
                ])

        print(f"[+] Results exported to: {output_file}")

    def _export_html(self, results: Dict, output_file: str):
        """Export results as HTML report with exploit code"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CVE Scan Report - {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 15px; background: #ecf0f1; border-radius: 5px; }}
        .stat-box h3 {{ margin: 0; color: #2c3e50; }}
        .stat-box p {{ font-size: 24px; font-weight: bold; margin: 10px 0 0 0; }}
        .critical {{ color: #c0392b; }}
        .high {{ color: #e67e22; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #27ae60; }}
        .cve-item {{ border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; background: #f8f9fa; }}
        .cve-item.CRITICAL {{ border-color: #c0392b; }}
        .cve-item.HIGH {{ border-color: #e67e22; }}
        .cve-item.MEDIUM {{ border-color: #f39c12; }}
        .cve-item.LOW {{ border-color: #27ae60; }}
        .tech-list {{ list-style: none; padding: 0; }}
        .tech-list li {{ padding: 8px; margin: 5px 0; background: #ecf0f1; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 CVE Scan Report</h1>
        <p><strong>Target:</strong> {url}</p>
        <p><strong>Scan Date:</strong> {date}</p>

        <div class="stats">
            <div class="stat-box">
                <h3>Technologies</h3>
                <p>{total_tech}</p>
            </div>
            <div class="stat-box">
                <h3>Total CVEs</h3>
                <p>{total_cves}</p>
            </div>
            <div class="stat-box">
                <h3 class="critical">Critical</h3>
                <p class="critical">{critical}</p>
            </div>
            <div class="stat-box">
                <h3 class="high">High</h3>
                <p class="high">{high}</p>
            </div>
            <div class="stat-box">
                <h3 class="medium">Medium</h3>
                <p class="medium">{medium}</p>
            </div>
            <div class="stat-box">
                <h3 class="low">Low</h3>
                <p class="low">{low}</p>
            </div>
        </div>

        <h2>📦 Detected Technologies</h2>
        <ul class="tech-list">
            {tech_list}
        </ul>

        <h2>🛡️ CVE Vulnerabilities</h2>
        {cve_list}
    </div>
</body>
</html>
"""

        # Build technology list
        tech_html = ""
        for tech in results['technologies']:
            version = tech['version'] if tech['version'] != 'unknown' else 'version unknown'
            tech_html += f"<li><strong>{tech['name']}</strong> {version} ({tech['category']})</li>\n"

        # Build CVE list with exploit code
        cve_html = ""

        # Create CVE ID to exploits mapping
        cve_exploit_map = {}
        for module in results.get('metasploit_modules', []):
            cve_id = module.get('related_cve')
            if cve_id:
                if cve_id not in cve_exploit_map:
                    cve_exploit_map[cve_id] = []
                cve_exploit_map[cve_id].append(module)

        for cve in results['cves']:
            exploit_badge = ' 💥 [EXPLOIT 있음]' if cve.get('has_exploit', False) else ''

            cve_html += f"""
            <div class="cve-item {cve['severity']}">
                <h3>{cve['cve_id']} - {cve['severity']} (CVSS: {cve['cvss_score']}){exploit_badge}</h3>
                <p><strong>Product:</strong> {cve['product']} {cve.get('specified_version', '')}</p>
                <p><strong>Published:</strong> {cve['published']}</p>
                <p><strong>Description:</strong> {cve['description']}</p>
            """

            # Add exploit information if available
            if cve['cve_id'] in cve_exploit_map:
                exploits = cve_exploit_map[cve['cve_id']]
                cve_html += f"""
                <div style="background: #fff3cd; padding: 15px; margin: 10px 0; border-left: 4px solid #ff6b6b;">
                    <h4 style="color: #d9534f; margin-top: 0;">💥 사용 가능한 Exploit: {len(exploits)}개</h4>
                """

                for idx, exploit in enumerate(exploits, 1):
                    cve_html += f"""
                    <div style="margin-bottom: 20px; background: white; padding: 15px; border: 1px solid #ddd;">
                        <h5 style="color: #333;">[{idx}] {exploit.get('name', 'Unknown')}</h5>
                        <p><strong>Exploit-DB ID:</strong> {exploit.get('edb_id', 'N/A')}</p>
                        <p><strong>플랫폼:</strong> {exploit.get('platform', 'Unknown')}</p>
                        <p><strong>타입:</strong> {exploit.get('type', 'Unknown')}</p>
                        <p><strong>URL:</strong> <a href="{exploit.get('url', '#')}" target="_blank">{exploit.get('url', '#')}</a></p>
                    """

                    # Add full exploit code if available
                    exploit_code_display = exploit.get('exploit_code_full') or exploit.get('exploit_code', '')
                    if exploit_code_display:
                        # HTML escape for safe display
                        import html
                        exploit_code_escaped = html.escape(exploit_code_display)

                        cve_html += f"""
                        <details style="margin-top: 10px;">
                            <summary style="cursor: pointer; font-weight: bold; color: #d9534f;">
                                📝 Exploit 코드 전문 보기 ({len(exploit_code_display.split(chr(10)))} lines)
                            </summary>
                            <pre style="background: #f5f5f5; padding: 15px; overflow-x: auto; border: 1px solid #ccc; margin-top: 10px; font-size: 11px; max-height: 600px;">{exploit_code_escaped}</pre>
                            <p style="margin-top: 10px;"><strong>원본 코드:</strong> <a href="{exploit.get('url', '#')}" target="_blank">{exploit.get('url', '#')}</a></p>
                        </details>
                        """

                    cve_html += "</div>"

                cve_html += "</div>"

            # Add references
            cve_html += f"""
                <p><strong>References:</strong></p>
                <ul>
                    {''.join([f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in cve.get('references', [])])}
                </ul>
            </div>
            """

        if not cve_html:
            cve_html = "<p>✅ No CVEs found!</p>"

        # Fill template
        from datetime import datetime
        html_content = html_template.format(
            url=results['url'],
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_tech=results['stats']['total_technologies'],
            total_cves=results['stats']['total_cves'],
            critical=results['stats']['critical'],
            high=results['stats']['high'],
            medium=results['stats']['medium'],
            low=results['stats']['low'],
            tech_list=tech_html,
            cve_list=cve_html
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"[+] HTML report exported to: {output_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='CVE Scanner - Web Application CVE Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python cve_scanner.py -u https://example.com
  python cve_scanner.py -u example.com --severity HIGH
  python cve_scanner.py -u https://target.com -o report.html --format html
  python cve_scanner.py -u https://site.com --api-key YOUR_NVD_API_KEY
  python cve_scanner.py -u https://site.com --metasploit

NVD API Key:
  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key
  Without key: 5 requests per 30 seconds
  With key: 50 requests per 30 seconds

Metasploit Search:
  Use --metasploit flag to search for exploit modules
  Searches GitHub and Exploit-DB for Metasploit modules
  Provides ready-to-use msfconsole commands
        '''
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('--no-cve', action='store_true', help='Skip CVE checking (only detect technologies)')
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        help='Filter CVEs by severity level')
    parser.add_argument('-o', '--output', help='Export results to file')
    parser.add_argument('--format', choices=['json', 'csv', 'html'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('--api-key', help='NVD API key for higher rate limits')
    parser.add_argument('--metasploit', action='store_true',
                        help='Search for Metasploit exploit modules')

    args = parser.parse_args()

    # Create scanner
    scanner = CVEScanner(nvd_api_key=args.api_key, search_metasploit=args.metasploit)

    # Run scan
    try:
        results = scanner.scan_url(
            url=args.url,
            check_cves=not args.no_cve,
            severity_filter=args.severity
        )

        # Export if requested
        if args.output:
            scanner.export_results(results, args.output, args.format)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
