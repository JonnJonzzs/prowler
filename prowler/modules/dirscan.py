import json
import os
from typing import Optional

from rich.console import Console

from prowler.runner import run_tool, tool_exists

console = Console()

MAX_HOSTS = 5


def run(
    alive_hosts: list[dict],
    wordlist: Optional[str],
    output_dir: str,
    threads: int = 50,
    passive: bool = False,
) -> dict:
    """
    Directory/endpoint discovery using ffuf against up to MAX_HOSTS alive HTTP services.
    Returns: {"endpoints": [{"url": "...", "status": 200, "size": 1234}]}
    """
    if passive:
        console.print("[yellow][DIRSCAN][/yellow] Skipping (--passive mode).")
        return {"endpoints": []}

    if not wordlist:
        console.print("[yellow][DIRSCAN][/yellow] No --wordlist provided, skipping ffuf.")
        return {"endpoints": []}

    if not os.path.isfile(wordlist):
        console.print(f"[bold red][DIRSCAN][/bold red] Wordlist not found: {wordlist}")
        return {"endpoints": []}

    if not tool_exists("ffuf"):
        console.print("[bold yellow][SKIP][/bold yellow] [yellow]DIRSCAN[/yellow]: 'ffuf' not found.")
        return {"endpoints": []}

    if not alive_hosts:
        console.print("[yellow][DIRSCAN][/yellow] No alive hosts to scan.")
        return {"endpoints": []}

    targets = alive_hosts[:MAX_HOSTS]
    console.print(
        f"[cyan][DIRSCAN][/cyan] Scanning {len(targets)} host(s) "
        f"(capped at {MAX_HOSTS} to stay non-aggressive)."
    )

    all_endpoints: list[dict] = []

    for i, host_info in enumerate(targets):
        base_url = host_info.get("url", "").rstrip("/")
        if not base_url:
            continue

        fuzz_url = f"{base_url}/FUZZ"
        out_file = os.path.join(output_dir, f"ffuf_{i}.json")

        cmd = [
            "ffuf",
            "-w", wordlist,
            "-u", fuzz_url,
            "-mc", "200,201,204,301,302,403",
            "-t", str(min(threads, 100)),
            "-o", out_file,
            "-of", "json",
            "-s",  # silent
        ]

        run_tool(cmd, f"DIRSCAN/ffuf [{base_url}]")

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    data = json.load(f)
                for result in data.get("results", []):
                    all_endpoints.append({
                        "url": result.get("url", ""),
                        "status": result.get("status", 0),
                        "size": result.get("length", 0),
                    })
            except (json.JSONDecodeError, KeyError):
                pass

    console.print(f"[bold green][DIRSCAN][/bold green] {len(all_endpoints)} endpoints found.")
    return {"endpoints": all_endpoints}
