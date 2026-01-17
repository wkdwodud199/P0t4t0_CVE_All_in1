#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Technology Stack Detector
Detects web technologies and their versions from HTTP responses
"""

import re
import requests
import hashlib
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Console encoding is handled by main script


class TechDetector:
    """Detects technologies used by a web application"""

    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.detected_technologies = []

    def scan(self, url: str) -> List[Dict]:
        """
        Scan a URL and detect all technologies with versions

        Returns:
            List of dicts: [{'name': 'Apache', 'version': '2.4.41', 'cpe': 'cpe:2.3:a:apache:http_server:2.4.41'}]
        """
        print(f"[*] Scanning: {url}\n")

        self.detected_technologies = []

        # Run all detection methods
        self._detect_from_headers(url)
        self._detect_from_html(url)
        self._detect_from_meta_tags(url)
        self._detect_from_files(url)
        self._detect_server_software(url)
        self._detect_cms(url)
        self._detect_javascript_libs(url)

        return self.detected_technologies

    def _add_technology(self, name: str, version: str = None, category: str = None):
        """Add detected technology to the list"""
        # Check if already exists
        for tech in self.detected_technologies:
            if tech['name'].lower() == name.lower():
                # Update version if we found a more specific one
                if version and (not tech['version'] or tech['version'] == 'unknown'):
                    tech['version'] = version
                return

        tech = {
            'name': name,
            'version': version or 'unknown',
            'category': category or 'unknown'
        }

        self.detected_technologies.append(tech)

        # Print detection
        if version and version != 'unknown':
            print(f"  [+] Detected: {name} {version} ({category or 'general'})")
        else:
            print(f"  [+] Detected: {name} ({category or 'general'})")

    def _detect_from_headers(self, url: str):
        """Detect technologies from HTTP headers"""
        print("[*] Analyzing HTTP headers...")

        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)

            # Server header
            if 'Server' in response.headers:
                server = response.headers['Server']
                self._parse_server_header(server)

            # X-Powered-By
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                self._parse_powered_by(powered_by)

            # Other headers
            header_mapping = {
                'X-AspNet-Version': ('ASP.NET', 'framework'),
                'X-AspNetMvc-Version': ('ASP.NET MVC', 'framework'),
                'X-Drupal-Cache': ('Drupal', 'cms'),
                'X-Generator': (None, 'cms'),  # Value contains the name
            }

            for header, (name, category) in header_mapping.items():
                if header in response.headers:
                    value = response.headers[header]
                    if name:
                        # Extract version from value
                        version_match = re.search(r'(\d+\.[\d.]+)', value)
                        version = version_match.group(1) if version_match else None
                        self._add_technology(name, version, category)
                    else:
                        # Header value contains the technology name
                        self._parse_generator(value)

        except Exception as e:
            print(f"  [!] Error analyzing headers: {str(e)}")

    def _parse_server_header(self, server_header: str):
        """Parse Server header to extract technologies"""
        # Examples:
        # Apache/2.4.41 (Ubuntu)
        # nginx/1.18.0
        # Microsoft-IIS/10.0

        patterns = {
            r'Apache[/\s]+([\d.]+)': ('Apache HTTP Server', 'web-server'),
            r'nginx[/\s]+([\d.]+)': ('nginx', 'web-server'),
            r'Microsoft-IIS[/\s]+([\d.]+)': ('Microsoft IIS', 'web-server'),
            r'lighttpd[/\s]+([\d.]+)': ('lighttpd', 'web-server'),
            r'LiteSpeed[/\s]+([\d.]+)': ('LiteSpeed', 'web-server'),
        }

        for pattern, (name, category) in patterns.items():
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                version = match.group(1)
                self._add_technology(name, version, category)

    def _parse_powered_by(self, powered_by: str):
        """Parse X-Powered-By header"""
        patterns = {
            r'PHP[/\s]+([\d.]+)': ('PHP', 'language'),
            r'Express': ('Express', 'framework'),
            r'ASP\.NET': ('ASP.NET', 'framework'),
        }

        for pattern, (name, category) in patterns.items():
            match = re.search(pattern, powered_by, re.IGNORECASE)
            if match:
                if '\\d' in pattern:
                    version = match.group(1)
                    self._add_technology(name, version, category)
                else:
                    self._add_technology(name, None, category)

    def _parse_generator(self, generator: str):
        """Parse generator/meta tag content"""
        patterns = {
            r'WordPress\s+([\d.]+)': ('WordPress', 'cms'),
            r'Joomla!?\s+([\d.]+)': ('Joomla', 'cms'),
            r'Drupal\s+([\d.]+)': ('Drupal', 'cms'),
        }

        for pattern, (name, category) in patterns.items():
            match = re.search(pattern, generator, re.IGNORECASE)
            if match:
                version = match.group(1)
                self._add_technology(name, version, category)

    def _detect_from_html(self, url: str):
        """Detect technologies from HTML content"""
        print("[*] Analyzing HTML content...")

        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for WordPress
            if soup.find('link', href=re.compile(r'/wp-content/')) or \
               soup.find('script', src=re.compile(r'/wp-includes/')):
                self._add_technology('WordPress', None, 'cms')
                # Try to get version from readme
                self._detect_wordpress_version(url)

            # Check for common patterns in scripts/links
            for tag in soup.find_all(['script', 'link']):
                src = tag.get('src', '') or tag.get('href', '')
                if src:
                    self._analyze_resource_url(src)

        except Exception as e:
            print(f"  [!] Error analyzing HTML: {str(e)}")

    def _analyze_resource_url(self, url: str):
        """Analyze script/link URLs for technology signatures"""
        patterns = {
            r'jquery[/-]([\d.]+)': ('jQuery', 'library'),
            r'bootstrap[/-]([\d.]+)': ('Bootstrap', 'library'),
            r'react[/-]([\d.]+)': ('React', 'library'),
            r'vue[/-]([\d.]+)': ('Vue.js', 'library'),
            r'angular[/-]([\d.]+)': ('Angular', 'library'),
        }

        for pattern, (name, category) in patterns.items():
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                version = match.group(1)
                self._add_technology(name, version, category)

    def _detect_from_meta_tags(self, url: str):
        """Detect from meta tags"""
        print("[*] Checking meta tags...")

        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Generator meta tag
            generator = soup.find('meta', attrs={'name': re.compile(r'generator', re.I)})
            if generator:
                content = generator.get('content', '')
                self._parse_generator(content)

        except Exception as e:
            print(f"  [!] Error checking meta tags: {str(e)}")

    def _detect_from_files(self, url: str):
        """Detect from common files"""
        print("[*] Probing common files...")

        common_files = {
            '/readme.html': self._check_wordpress_readme,
            '/composer.json': self._check_composer,
            '/package.json': self._check_package_json,
        }

        for path, handler in common_files.items():
            try:
                file_url = urljoin(url, path)
                response = self.session.get(file_url, timeout=5, verify=self.verify_ssl)
                if response.status_code == 200:
                    handler(response.text)
            except:
                continue

    def _check_wordpress_readme(self, content: str):
        """Check WordPress readme.html for version"""
        match = re.search(r'Version\s+([\d.]+)', content)
        if match:
            self._add_technology('WordPress', match.group(1), 'cms')

    def _check_composer(self, content: str):
        """Check composer.json for PHP packages"""
        try:
            import json
            data = json.loads(content)
            if 'require' in data:
                for package, version in data['require'].items():
                    if 'php' in package.lower():
                        # Extract version number from constraint
                        version_match = re.search(r'(\d+\.[\d.]+)', version)
                        if version_match:
                            self._add_technology('PHP', version_match.group(1), 'language')
        except:
            pass

    def _check_package_json(self, content: str):
        """Check package.json for Node.js dependencies"""
        try:
            import json
            data = json.loads(content)

            # Check dependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for package, version in data[dep_type].items():
                        # Extract clean version
                        version_match = re.search(r'(\d+\.[\d.]+)', version)
                        clean_version = version_match.group(1) if version_match else None

                        # Map common packages
                        package_mapping = {
                            'react': ('React', 'library'),
                            'vue': ('Vue.js', 'library'),
                            'angular': ('Angular', 'library'),
                            'express': ('Express', 'framework'),
                            'next': ('Next.js', 'framework'),
                        }

                        if package in package_mapping:
                            name, category = package_mapping[package]
                            self._add_technology(name, clean_version, category)
        except:
            pass

    def _detect_server_software(self, url: str):
        """Detect server software from error pages"""
        print("[*] Testing error pages...")

        error_paths = ['/nonexistent-page-404', '/.env']

        for path in error_paths:
            try:
                error_url = urljoin(url, path)
                response = self.session.get(error_url, timeout=5, verify=self.verify_ssl)

                # Look for version patterns in error pages
                patterns = {
                    r'Apache[/\s]+([\d.]+)': ('Apache HTTP Server', 'web-server'),
                    r'nginx[/\s]+([\d.]+)': ('nginx', 'web-server'),
                    r'PHP[/\s]+([\d.]+)': ('PHP', 'language'),
                    r'OpenSSL[/\s]+([\d.]+)': ('OpenSSL', 'library'),
                    r'mod_ssl[/\s]+([\d.]+)': ('mod_ssl', 'module'),
                }

                for pattern, (name, category) in patterns.items():
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        self._add_technology(name, matches[0], category)
                        break
            except:
                continue

    def _detect_wordpress_version(self, url: str):
        """Try to detect WordPress version"""
        version_endpoints = [
            '/wp-includes/version.php',
            '/readme.html',
        ]

        for endpoint in version_endpoints:
            try:
                version_url = urljoin(url, endpoint)
                response = self.session.get(version_url, timeout=5, verify=self.verify_ssl)
                if response.status_code == 200:
                    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', response.text)
                    if match:
                        self._add_technology('WordPress', match.group(1), 'cms')
                        return
            except:
                continue

    def _detect_cms(self, url: str):
        """Detect CMS-specific signatures"""
        print("[*] Checking for CMS...")

        cms_signatures = {
            'Joomla': ['/administrator/manifests/files/joomla.xml'],
            'Drupal': ['/CHANGELOG.txt', '/core/CHANGELOG.txt'],
            'Magento': ['/magento_version'],
        }

        for cms, paths in cms_signatures.items():
            for path in paths:
                try:
                    cms_url = urljoin(url, path)
                    response = self.session.get(cms_url, timeout=5, verify=self.verify_ssl)
                    if response.status_code == 200:
                        # Try to extract version
                        version_match = re.search(r'[Vv]ersion[:\s]+(\d+\.[\d.]+)', response.text[:2000])
                        version = version_match.group(1) if version_match else None
                        self._add_technology(cms, version, 'cms')
                        break
                except:
                    continue

    def _detect_javascript_libs(self, url: str):
        """Detect JavaScript libraries"""
        print("[*] Detecting JavaScript libraries...")

        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            content = response.text

            # Pattern matching for common libraries
            patterns = {
                r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.[\d.]+)["\']': ('jQuery', 'library'),
                r'Vue\.version\s*=\s*["\'](\d+\.[\d.]+)["\']': ('Vue.js', 'library'),
            }

            for pattern, (name, category) in patterns.items():
                match = re.search(pattern, content)
                if match:
                    self._add_technology(name, match.group(1), category)

        except Exception as e:
            pass

    def get_results(self) -> List[Dict]:
        """Get all detected technologies"""
        return self.detected_technologies

    def print_summary(self):
        """Print detection summary"""
        print("\n" + "="*70)
        print("TECHNOLOGY DETECTION SUMMARY")
        print("="*70)

        if not self.detected_technologies:
            print("No technologies detected.")
            return

        # Group by category
        categories = {}
        for tech in self.detected_technologies:
            cat = tech['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tech)

        for category, techs in sorted(categories.items()):
            print(f"\n{category.upper()}:")
            for tech in techs:
                if tech['version'] != 'unknown':
                    print(f"  • {tech['name']} {tech['version']}")
                else:
                    print(f"  • {tech['name']}")

        print("\n" + "="*70)
