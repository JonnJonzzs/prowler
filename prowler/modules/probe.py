import json
import os
import tempfile

from rich.console import Console

from prowler.runner import run_tool, tool_exists

console = Console()


def run(subdomains: list[str], output_dir: str, threads: int = 50, passive: bool = False) -> dict:
    """
    Probe subdomains with httpx to find alive HTTP/HTTPS services.
    Returns: {"alive": [{"url": "...", "status": 200, "title": "...", "length": 1234}]}
    """
    if not subdomains:
        console.print("[yellow][PROBE][/yellow] No subdomains to probe.")
        return {"alive": []}

    if not tool_exists("httpx"):
        console.print("[bold yellow][SKIP][/bold yellow] [yellow]PROBE[/yellow]: 'httpx' not found — install projectdiscovery/httpx.")
        return {"alive": []}

    # Write subdomains to a temp file
    subs_file = os.path.join(output_dir, "subdomains.txt")
    with open(subs_file, "w") as f:
        f.write("\n".join(subdomains))

    json_out = os.path.join(output_dir, "httpx_out.json")

    cmd = [
        "httpx",
        "-l", subs_file,
        "-silent",
        "-status-code",
        "-title",
        "-content-length",
        "-json",
        "-threads", str(threads),
        "-o", json_out,
    ]

    run_tool(cmd, "PROBE/httpx")

    alive: list[dict] = []

    # httpx -json writes one JSON object per line
    if os.path.exists(json_out):
        with open(json_out) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    alive.append({
                        "url": entry.get("url", ""),
                        "status": entry.get("status-code", entry.get("status_code", 0)),
                        "title": entry.get("title", ""),
                        "length": entry.get("content-length", entry.get("content_length", 0)),
                    })
                except json.JSONDecodeError:
                    pass

    console.print(f"[bold green][PROBE][/bold green] {len(alive)} alive hosts discovered.")
    return {"alive": alive}
