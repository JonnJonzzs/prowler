# prowler

Automated recon pipeline for bug bounty hunting. Wraps `subfinder`/`amass`, `nmap`, `httpx`, and `ffuf` into a single command with live terminal output and an HTML report.

> **DISCLAIMER:** Only use this tool against targets you have explicit written permission to test. Unauthorized scanning is illegal.

---

## Install

```bash
pip install -e .
```

> Requires Python 3.10+. Install the external tools separately (see below).

---

## External tool dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Subdomain discovery (preferred) | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | Subdomain discovery (fallback) | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| `httpx` | HTTP probe | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `nmap` | Port scanning | `sudo apt install nmap` / `brew install nmap` |
| `ffuf` | Directory/endpoint fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |

reconx **gracefully skips** any module whose tool is not installed, so you can use it with just a subset of tools.

---

## Usage

```bash
# Full pipeline (all modules)
reconx example.com

# Only subdomain enumeration + HTTP probe
reconx example.com --modules subdomains,probe

# Full pipeline with directory fuzzing
reconx example.com --wordlist /usr/share/wordlists/dirb/common.txt

# Passive only (no nmap / ffuf)
reconx example.com --passive

# Custom output directory and thread count
reconx example.com --output-dir ./my_recon --threads 100
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `domain` | required | Target domain |
| `--modules` | all | Comma-separated: `subdomains,probe,portscan,dirscan` |
| `--output-dir` | `./recon_<domain>_<ts>` | Where to save results |
| `--wordlist` | none | Wordlist for ffuf (skips dirscan if omitted) |
| `--threads` | 50 | Thread count passed to tools |
| `--passive` | off | Passive recon only (skips nmap + ffuf) |

---

## Output

Each run creates an output directory containing:

```
recon_example.com_20240101_120000/
├── subdomains.txt        # Raw subdomain list fed to httpx
├── httpx_out.json        # Raw httpx JSON
├── ffuf_0.json           # Raw ffuf output per host
├── report.json           # Full structured results
└── report.html           # Self-contained dark-theme HTML report
```

The HTML report includes:
- Summary card (counts for each finding type)
- Collapsible sections per module
- Sortable tables for subdomains, alive services, open ports, and endpoints

---

## Pipeline order

```
subdomains  →  probe  →  portscan  →  dirscan
    |              |
    └──────────────┘
    subdomains list fed into probe
```

---

## Module output format

```python
subdomains: {"subdomains": ["sub1.example.com", ...]}
probe:      {"alive": [{"url": "https://...", "status": 200, "title": "...", "length": 1234}]}
portscan:   {"hosts": [{"host": "1.2.3.4", "ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}]}
dirscan:    {"endpoints": [{"url": "https://.../admin", "status": 200, "size": 512}]}
```
