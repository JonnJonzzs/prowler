# -*- coding: utf-8 -*-
import argparse
import os
import sys
from datetime import datetime

# Ensure stdout/stderr can handle Unicode on terminals that default to ASCII
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from prowler import __version__
from prowler.modules import dirscan, portscan, probe, subdomains
from prowler import report

console = Console()

BANNER = f"""[bold cyan]
██████╗ ██████╗  ██████╗ ██╗    ██╗██╗     ███████╗██████╗
██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║     ██╔════╝██╔══██╗
██████╔╝██████╔╝██║   ██║██║ █╗ ██║██║     █████╗  ██████╔╝
██╔═══╝ ██╔══██╗██║   ██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╔╝╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝[/bold cyan]
[dim]                              Bug Bounty Recon Automation v{__version__}[/dim]"""

DISCLAIMER = (
    "[bold red]DISCLAIMER:[/bold red] This tool is for [bold]authorized[/bold] security testing only.\n"
    "Using prowler against targets without explicit written permission is illegal and unethical.\n"
    "[dim]Always hunt on authorized bug bounty programs.[/dim]"
)

ALL_MODULES = ["subdomains", "probe", "portscan", "dirscan"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="prowler",
        description="Automated recon pipeline for bug bounty hunting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  prowler example.com\n"
            "  prowler example.com --modules subdomains,probe\n"
            "  prowler example.com --wordlist /usr/share/wordlists/dirb/common.txt --threads 100\n"
            "  prowler example.com --passive\n"
        ),

    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--modules",
        default=",".join(ALL_MODULES),
        help=f"Comma-separated list of modules to run (default: all). Choices: {', '.join(ALL_MODULES)}",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to save results (default: ./recon_<domain>_<timestamp>)",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Path to wordlist for ffuf directory scanning",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Thread count passed to underlying tools (default: 50)",
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Only passive recon (skips nmap and ffuf)",
    )
    return parser.parse_args()


def resolve_output_dir(domain: str, cli_path: str | None) -> str:
    if cli_path:
        out = cli_path
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = os.path.join(os.getcwd(), f"recon_{domain}_{ts}")
    os.makedirs(out, exist_ok=True)
    return out


def main() -> None:
    args = parse_args()
    domain = args.domain.strip().lower()

    # Validate requested modules
    requested = [m.strip() for m in args.modules.split(",") if m.strip()]
    invalid = [m for m in requested if m not in ALL_MODULES]
    if invalid:
        console.print(f"[bold red]Unknown module(s):[/bold red] {', '.join(invalid)}. Valid: {', '.join(ALL_MODULES)}")
        sys.exit(1)

    console.print(BANNER)
    console.print(Panel(DISCLAIMER, border_style="red", padding=(1, 2)))
    console.print()

    output_dir = resolve_output_dir(domain, args.output_dir)
    console.print(f"[bold]Target:[/bold]     [cyan]{domain}[/cyan]")
    console.print(f"[bold]Modules:[/bold]    [cyan]{', '.join(requested)}[/cyan]")
    console.print(f"[bold]Output:[/bold]     [cyan]{output_dir}[/cyan]")
    console.print(f"[bold]Threads:[/bold]    [cyan]{args.threads}[/cyan]")
    if args.passive:
        console.print("[bold yellow]Mode:[/bold yellow]       Passive only")
    console.print()

    results: dict = {"domain": domain, "scan_date": datetime.now().isoformat()}

    # ── 1. Subdomain Enumeration ────────────────────────────────────────────
    if "subdomains" in requested:
        console.print(Rule("[bold cyan]Step 1/4 — Subdomain Enumeration[/bold cyan]"))
        sub_results = subdomains.run(
            domain=domain,
            output_dir=output_dir,
            threads=args.threads,
            passive=args.passive,
        )
        results["subdomains"] = sub_results
    else:
        results["subdomains"] = {"subdomains": [domain]}

    found_subs = results["subdomains"].get("subdomains", [domain])

    # ── 2. HTTP Probe ───────────────────────────────────────────────────────
    if "probe" in requested:
        console.print(Rule("[bold cyan]Step 2/4 — HTTP Probe[/bold cyan]"))
        probe_results = probe.run(
            subdomains=found_subs,
            output_dir=output_dir,
            threads=args.threads,
            passive=args.passive,
        )
        results["probe"] = probe_results
    else:
        results["probe"] = {"alive": []}

    alive_hosts = results["probe"].get("alive", [])

    # ── 3. Port Scan ────────────────────────────────────────────────────────
    if "portscan" in requested:
        console.print(Rule("[bold cyan]Step 3/4 — Port Scan[/bold cyan]"))
        # Use alive host URLs stripped to hostnames, fall back to found subdomains
        if alive_hosts:
            from urllib.parse import urlparse
            targets = list({urlparse(h["url"]).hostname for h in alive_hosts if h.get("url")})
        else:
            targets = found_subs[:20]  # cap to avoid runaway scans

        portscan_results = portscan.run(
            targets=targets,
            output_dir=output_dir,
            threads=args.threads,
            passive=args.passive,
        )
        results["portscan"] = portscan_results
    else:
        results["portscan"] = {"hosts": []}

    # ── 4. Directory Scan ───────────────────────────────────────────────────
    if "dirscan" in requested:
        console.print(Rule("[bold cyan]Step 4/4 — Directory / Endpoint Discovery[/bold cyan]"))
        dirscan_results = dirscan.run(
            alive_hosts=alive_hosts,
            wordlist=args.wordlist,
            output_dir=output_dir,
            threads=args.threads,
            passive=args.passive,
        )
        results["dirscan"] = dirscan_results
    else:
        results["dirscan"] = {"endpoints": []}

    # ── Save reports ────────────────────────────────────────────────────────
    console.print(Rule("[bold green]Saving Reports[/bold green]"))

    json_path = os.path.join(output_dir, "report.json")
    html_path = os.path.join(output_dir, "report.html")

    report.save_json(results, json_path)
    report.save_html(results, domain, html_path)

    console.print()
    console.print(
        Panel(
            f"[bold green]Scan complete![/bold green]\n\n"
            f"  [bold]JSON report:[/bold] {json_path}\n"
            f"  [bold]HTML report:[/bold] [link=file://{html_path}]{html_path}[/link]",
            title="[bold]reconx[/bold]",
            border_style="green",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
