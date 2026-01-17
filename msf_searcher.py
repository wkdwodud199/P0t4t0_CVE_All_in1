#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metasploit Module Searcher
Searches for available Metasploit exploit modules for CVEs
"""

import requests
import re
import sys
import io
from typing import List, Dict, Optional

# Fix Windows console encoding for standalone execution
if sys.platform == 'win32':
    if not isinstance(sys.stdout, io.TextIOWrapper) or sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
        except:
            pass


class MetasploitSearcher:
    """Search for Metasploit exploit modules"""

    # Rapid7 Metasploit module database (JSON API)
    RAPID7_API = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

    # Alternative: search via GitHub API
    GITHUB_SEARCH_API = "https://api.github.com/search/code"

    def __init__(self):
        """Initialize Metasploit searcher"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVE-Scanner/1.0'
        })
        self.modules_cache = None

    def search_by_cve(self, cve_id: str) -> List[Dict]:
        """
        Search for Metasploit modules by CVE ID

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            List of matching Metasploit modules and exploits
        """
        print(f"\n[*] {cve_id}에 대한 exploit 데이터베이스 검색 중...")

        modules = []

        # Primary: CIRCL API 검색 (Exploit-DB와 Metasploit 모두 포함)
        circl_modules = self._search_circl_api(cve_id)
        modules.extend(circl_modules)

        # Fallback: CIRCL이 결과를 반환하지 않으면 GitHub 검색
        if not circl_modules:
            github_modules = self._search_github(cve_id)
            modules.extend(github_modules)

        if modules:
            print(f"  [+] {len(modules)}개의 exploit/모듈을 찾았습니다")
        else:
            print(f"  [-] {cve_id}에 대한 exploit을 찾지 못했습니다")

        return modules

    def search_by_product(self, product_name: str, version: str = None) -> List[Dict]:
        """
        Search for Metasploit modules by product name

        Args:
            product_name: Product name (e.g., "Apache HTTP Server")
            version: Optional version

        Returns:
            List of matching Metasploit modules
        """
        print(f"\n[*] Searching Metasploit modules for {product_name}" +
              (f" {version}" if version else "") + "...")

        # Clean product name for search
        search_term = product_name.lower().replace(' ', '_')

        modules = self._search_github(search_term)

        if modules:
            print(f"  [+] Found {len(modules)} Metasploit module(s)")
        else:
            print(f"  [-] No Metasploit modules found")

        return modules

    def _search_circl_api(self, cve_id: str) -> List[Dict]:
        """
        Exploit-DB 검색 API를 사용하여 exploit 정보 검색

        실제 exploit 코드도 함께 가져옴

        Args:
            cve_id: CVE 식별자

        Returns:
            모듈 정보 리스트 (exploit 코드 포함)
        """
        modules = []

        try:
            # Exploit-DB 검색 (CVE로 검색)
            # www.exploit-db.com은 검색 페이지를 스크래핑하는 방식
            search_url = f"https://www.exploit-db.com/search?cve={cve_id}"

            # 대신 GitLab의 searchsploit DB를 JSON으로 검색
            # https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
            csv_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

            response = self.session.get(csv_url, timeout=15)

            if response.status_code == 200:
                lines = response.text.split('\n')

                for line in lines[1:]:  # Skip header
                    if cve_id.upper() in line.upper():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            edb_id = parts[0].strip('"')
                            platform = parts[1].strip('"') if len(parts) > 1 else 'Unknown'
                            name = parts[2].strip('"') if len(parts) > 2 else 'Unknown'

                            module_info = {
                                'name': name,
                                'edb_id': edb_id,
                                'source': 'Exploit-DB',
                                'url': f"https://www.exploit-db.com/exploits/{edb_id}",
                                'platform': platform,
                                'type': parts[3].strip('"') if len(parts) > 3 else 'Unknown'
                            }

                            # Exploit 코드 가져오기 (중요!)
                            exploit_code = self._fetch_exploit_code(edb_id)
                            if exploit_code:
                                module_info['exploit_code'] = exploit_code
                                module_info['has_code'] = True

                            modules.append(module_info)

        except Exception as e:
            print(f"  [!] Exploit-DB 검색 오류: {str(e)}")

        return modules

    def _fetch_exploit_code(self, edb_id: str, full_code: bool = False) -> Optional[str]:
        """
        Exploit-DB에서 실제 exploit 코드를 가져옴

        Args:
            edb_id: Exploit-DB ID
            full_code: True이면 전체 코드, False이면 처음 50줄만

        Returns:
            Exploit 코드 또는 None
        """
        try:
            # Exploit-DB raw URL
            raw_url = f"https://www.exploit-db.com/raw/{edb_id}"
            response = self.session.get(raw_url, timeout=5)

            if response.status_code == 200:
                code = response.text
                if full_code:
                    # 전체 코드 반환
                    return code
                else:
                    # 처음 50줄만 반환 (터미널 출력용)
                    lines = code.split('\n')[:50]
                    return '\n'.join(lines)
        except:
            pass

        return None

    def _search_github(self, query: str) -> List[Dict]:
        """
        Search Metasploit modules via GitHub Code Search API

        Args:
            query: Search term (CVE ID or product name)

        Returns:
            List of module information
        """
        modules = []

        try:
            # Search in Metasploit Framework repository
            params = {
                'q': f'{query} repo:rapid7/metasploit-framework path:modules/exploits',
                'per_page': 10
            }

            response = self.session.get(
                self.GITHUB_SEARCH_API,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])

                for item in items:
                    module_info = {
                        'name': item.get('name', 'Unknown'),
                        'path': item.get('path', ''),
                        'url': item.get('html_url', ''),
                        'repository': item.get('repository', {}).get('full_name', ''),
                        'source': 'Metasploit Framework (GitHub)'
                    }

                    # Extract module path (e.g., exploit/windows/http/xyz)
                    path = module_info['path']
                    if 'modules/exploits/' in path:
                        msf_path = path.split('modules/exploits/')[1].replace('.rb', '')
                        module_info['msf_path'] = f"exploit/{msf_path}"
                    elif 'modules/auxiliary/' in path:
                        msf_path = path.split('modules/auxiliary/')[1].replace('.rb', '')
                        module_info['msf_path'] = f"auxiliary/{msf_path}"

                    modules.append(module_info)

            elif response.status_code == 403:
                print("  [!] GitHub API rate limit exceeded. Try again later.")

        except Exception as e:
            print(f"  [!] Error searching GitHub: {str(e)}")

        return modules

    def _search_exploitdb(self, cve_id: str) -> List[Dict]:
        """
        Search Exploit-DB for Metasploit modules

        Args:
            cve_id: CVE identifier

        Returns:
            List of module information
        """
        modules = []

        try:
            # Exploit-DB CSV database
            exploitdb_url = f"https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

            response = self.session.get(exploitdb_url, timeout=15)

            if response.status_code == 200:
                content = response.text
                lines = content.split('\n')

                for line in lines:
                    # Check if line contains CVE ID and Metasploit
                    if cve_id.upper() in line.upper() and 'metasploit' in line.lower():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            module_info = {
                                'name': parts[2].strip('"') if len(parts) > 2 else 'Unknown',
                                'edb_id': parts[0],
                                'platform': parts[1] if len(parts) > 1 else 'Unknown',
                                'source': 'Exploit-DB',
                                'url': f"https://www.exploit-db.com/exploits/{parts[0]}"
                            }
                            modules.append(module_info)

        except Exception as e:
            # Silently fail - Exploit-DB search is optional
            pass

        return modules

    def get_module_details(self, module_path: str) -> Optional[Dict]:
        """
        Get details for a specific Metasploit module

        Args:
            module_path: Module path (e.g., "exploit/windows/smb/ms17_010_eternalblue")

        Returns:
            Module details dictionary
        """
        try:
            # Construct GitHub raw URL
            base_url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/"
            file_path = module_path.replace('exploit/', 'exploits/').replace('auxiliary/', 'auxiliary/') + '.rb'
            url = base_url + file_path

            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                content = response.text

                # Parse module metadata
                details = {
                    'path': module_path,
                    'source_url': url
                }

                # Extract name
                name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", content)
                if name_match:
                    details['name'] = name_match.group(1)

                # Extract description
                desc_match = re.search(r"'Description'\s*=>\s*%q\{([^}]+)\}", content)
                if desc_match:
                    details['description'] = desc_match.group(1).strip()

                # Extract author
                author_match = re.search(r"'Author'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
                if author_match:
                    details['author'] = author_match.group(1).strip()

                # Extract references (CVE, URL, etc.)
                references = []
                ref_section = re.search(r"'References'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
                if ref_section:
                    ref_content = ref_section.group(1)
                    cve_refs = re.findall(r"\['CVE',\s*'([^']+)'\]", ref_content)
                    references.extend([f"CVE-{cve}" for cve in cve_refs])

                details['references'] = references

                # Extract disclosure date
                date_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", content)
                if date_match:
                    details['disclosure_date'] = date_match.group(1)

                # Extract targets
                targets_match = re.search(r"'Targets'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
                if targets_match:
                    details['targets'] = 'Available'

                return details

        except Exception as e:
            print(f"  [!] Error fetching module details: {str(e)}")

        return None

    def print_module_report(self, modules: List[Dict]):
        """Exploit 모듈 리포트 출력 (exploit 코드 포함)"""
        if not modules:
            return

        print("\n" + "="*80)
        print("EXPLOIT 모듈 및 코드")
        print("="*80)

        for idx, module in enumerate(modules, 1):
            print(f"\n[{idx}] {module.get('name', 'Unknown')}")

            # Metasploit 모듈 정보
            if 'msf_path' in module:
                print(f"    경로: {module['msf_path']}")
                print(f"    사용법: msfconsole -x 'use {module['msf_path']}'")

            # Exploit-DB 정보
            if 'edb_id' in module:
                print(f"    Exploit-DB ID: {module['edb_id']}")
                print(f"    플랫폼: {module.get('platform', 'Unknown')}")
                print(f"    타입: {module.get('type', 'Unknown')}")

            if 'url' in module:
                print(f"    URL: {module['url']}")

            print(f"    출처: {module.get('source', 'Unknown')}")

            # Exploit 코드 표시
            if 'exploit_code' in module and module['exploit_code']:
                print(f"\n    {'─'*76}")
                print(f"    [Exploit 코드 미리보기 (처음 50줄)]")
                print(f"    {'─'*76}")
                # 코드의 각 줄 앞에 4칸 들여쓰기
                code_lines = module['exploit_code'].split('\n')
                for line in code_lines:
                    print(f"    {line}")
                print(f"    {'─'*76}")
                print(f"    전체 코드: {module['url']}")
                print(f"    {'─'*76}")

        print("\n" + "="*80)

    def generate_msf_commands(self, modules: List[Dict]) -> List[str]:
        """
        Generate ready-to-use msfconsole commands

        Args:
            modules: List of Metasploit modules

        Returns:
            List of msfconsole commands
        """
        commands = []

        for module in modules:
            if 'msf_path' in module:
                # Basic usage command
                cmd = f"use {module['msf_path']}\nshow options\nshow targets"
                commands.append({
                    'module': module['msf_path'],
                    'command': cmd,
                    'description': module.get('name', 'Unknown module')
                })

        return commands


def test_msf_searcher():
    """Test Metasploit searcher"""
    searcher = MetasploitSearcher()

    # Test CVE search
    test_cves = [
        "CVE-2017-0143",  # EternalBlue
        "CVE-2021-44228",  # Log4Shell
        "CVE-2014-0160",   # Heartbleed
    ]

    for cve in test_cves:
        modules = searcher.search_by_cve(cve)
        searcher.print_module_report(modules)

        if modules:
            commands = searcher.generate_msf_commands(modules)
            if commands:
                print("\n[*] Ready-to-use commands:")
                for cmd_info in commands[:3]:
                    print(f"\n# {cmd_info['description']}")
                    print(f"msfconsole -x '{cmd_info['command']}'")


if __name__ == '__main__':
    test_msf_searcher()
