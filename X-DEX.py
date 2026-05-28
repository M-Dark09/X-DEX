#!/usr/bin/env python3

"""
Mini outil d'analyse Web en Python
----------------------------------
Fonctions:
- Analyse les en-têtes HTTP/HTTPS
- Suit les redirections
- Récupère les endpoints/liens trouvés dans le HTML
- Détecte les technologies via les headers
- Sauvegarde les résultats en JSON

Usage:
    python3 web_analyzer.py https://example.com

Dépendances:
    pip install requests beautifulsoup4
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import sys
import re
from collections import deque
from rich.console import Console

console = Console()

class WebAnalyzer:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.visited = set()
        self.results = {
            "target": self.base_url,
            "headers": {},
            "redirects": [],
            "endpoints": [],
            "technologies": [],
            "cookies": [],
            "security_headers": {}
        }

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; WebAnalyzer/1.0)"
        })

    def detect_technologies(self, headers, html=""):
        techs = []

        server = headers.get("Server")
        powered = headers.get("X-Powered-By")

        if server:
           techs.append(f"Server: {server}")

        if powered:
           techs.append(f"Powered-By: {powered}")

        html_lower = html.lower()

        patterns = {
            "WordPress": r"wp-content|wordpress",
            "Laravel": r"laravel",
            "React": r"react",
            "Vue.js": r"vue",
            "Angular": r"angular",
            "jQuery": r"jquery",
            "Bootstrap": r"bootstrap"
        }

        for name, pattern in patterns.items():
            if re.search(pattern, html_lower):
                techs.append(name)

        return list(set(techs))

    def analyze_headers(self, response):
        headers = dict(response.headers)
        self.results["headers"] = headers

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        for header in security_headers:
            self.results["security_headers"][header] = headers.get(header, "Absent")

        if response.cookies:
            for cookie in response.cookies:
                self.results["cookies"].append({
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly")
                })

        return headers

    def extract_endpoints(self, html, current_url):
        soup = BeautifulSoup(html, "html.parser")
        found_urls = set()

        tags_attrs = {
            "a": "href",
            "script": "src",
            "link": "href",
            "img": "src",
            "form": "action"
        }

        for tag, attr in tags_attrs.items():
            for element in soup.find_all(tag):
                url = element.get(attr)

                if not url:
                    continue

                full_url = urljoin(current_url, url)
                parsed = urlparse(full_url)

                if parsed.scheme in ["http", "https"]:
                    found_urls.add(full_url)

        api_patterns = re.findall(
            r'/(api|v1|v2|graphql|auth|login|admin|dashboard)[^"\'\s<>]*',
            html,
            re.IGNORECASE
        )

        for endpoint in api_patterns:
            found_urls.add(urljoin(current_url, endpoint))

        return list(found_urls)

    def follow_redirects(self, response):
        history = response.history

        for redirect in history:
            self.results["redirects"].append({
                "from": redirect.url,
                "to": response.url,
                "status": redirect.status_code
            })

    def crawl(self):
        queue = deque([(self.base_url, 0)])

        while queue:
            current_url, depth = queue.popleft()

            if current_url in self.visited:
                continue

            if depth > self.max_depth:
                continue

            console.print(f"[+] Analyse: {current_url}")
            self.visited.add(current_url)

            try:
                response = self.session.get(
                    current_url,
                    timeout=10,
                    allow_redirects=True,
                    verify=True
                )

                self.follow_redirects(response)
                self.analyze_headers(response)

                html = response.text

                techs = self.detect_technologies(response.headers, html)
                self.results["technologies"].extend(techs)

                endpoints = self.extract_endpoints(html, current_url)

                for endpoint in endpoints:
                    if endpoint not in self.results["endpoints"]:
                        self.results["endpoints"].append(endpoint)

                    parsed_base = urlparse(self.base_url).netloc
                    parsed_endpoint = urlparse(endpoint).netloc

                    if parsed_base == parsed_endpoint:
                        queue.append((endpoint, depth + 1))

            except requests.exceptions.RequestException as e:
                console.print(f"[-] Erreur sur {current_url}: {e}")

        self.results["technologies"] = list(set(self.results["technologies"]))

    def save_results(self, filename="results.json"):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)

        print(f"\n[+] Résultats sauvegardés dans: {filename}")

    def print_summary(self):
        print("\n========== RÉSUMÉ ==========")

        print("\n[HEADERS]")
        for key, value in self.results["headers"].items():
            print(f"{key}: {value}")

        print("\n[REDIRECTIONS]")
        for r in self.results["redirects"]:
            print(f"{r['status']} | {r['from']} -> {r['to']}")

        print("\n[TECHNOLOGIES]")
        for tech in self.results["technologies"]:
            print(f"- {tech}")

        print("\n[ENDPOINTS TROUVÉS]")
        for endpoint in self.results["endpoints"]:
            print(f"- {endpoint}")

        print("\n[SECURITY HEADERS]")
        for key, value in self.results["security_headers"].items():
            print(f"{key}: {value}")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} https://example.com")
        sys.exit(1)

    target = sys.argv[1]

    analyzer = WebAnalyzer(target, max_depth=2)
    analyzer.crawl()
    analyzer.print_summary()
    analyzer.save_results()


if __name__ == "__main__":
    main()
