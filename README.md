# pathraider

Offensive LFD and Directory Traversal scanner.

> 🇪🇸 [Versión en español](README.es.md)

---

## What does it do?

Checks whether a web application parameter allows reading local system files (LFD / Path Traversal). It generates traversal variants and encoding bypasses as a fast first-pass tool.

Important: findings are candidates, not confirmed vulnerabilities.

---

## Features

- Single target (`--url`) or multiple targets from file (`--list`)
- Injection via `FUZZ` marker or configurable parameter (`--param`)
- Multiple traversal encodings and null-byte variants
- Heuristic detection of sensitive content (`/etc/passwd`, `win.ini`, etc.)
- Concurrent scanning with threads
- Normalized findings output
- JSON / JSONL export
- `stdout` mode for pipelines
- Clean `Ctrl+C` handling

---

## Installation

```bash
git clone https://github.com/theoffsecgirl/pathraider.git
cd pathraider
pip install -e .
```

---

## Usage

```bash
pathraider -u "https://example.com/download.php?file=FUZZ"
```

### Pipeline

```bash
pathraider -u "https://target.com/download?file=FUZZ" --format jsonl --stdout | bbcopilot ingest pathraider -
```

### Save normalized findings

```bash
pathraider -L scope.txt --format jsonl --findings-output findings.jsonl
```

---

## Parameters

```text
-u, --url                Target URL (can contain FUZZ)
-L, --list               File with list of targets
--paths                  Custom traversal paths
-p, --param              Parameter without FUZZ (default: file)
-t, --timeout            Timeout per request (default: 5)
-T, --threads            Threads per target (default: 10)
-A, --agent              Custom User-Agent
--insecure               Disable TLS verification
--json-output            Save classic report to JSON
--format json|jsonl      Normalized findings format
--stdout                 Print normalized findings to stdout
--findings-output        Save normalized findings to a file
-v, --verbose            Verbose mode
--version                Show version
```

---

## Notes

- Logs go to `stderr`
- Findings go to `stdout` with `--stdout`
- `Ctrl+C` exits cleanly
- Designed for bug bounty recon and pipeline integration

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## License

MIT
