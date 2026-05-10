from rich.console import Console

from prowler.runner import run_tool, tool_exists

console = Console()


def run(domain: str, output_dir: str, threads: int = 50, passive: bool = False) -> dict:
    """
    Enumerate subdomains using subfinder (preferred) or amass as fallback.
    Returns: {"subdomains": ["sub1.example.com", ...]}
    """
    subdomains: list[str] = []

    if tool_exists("subfinder"):
        cmd = ["subfinder", "-d", domain, "-silent", "-t", str(threads)]
        output = run_tool(cmd, "SUBDOMAINS/subfinder")
    elif tool_exists("amass"):
        cmd = ["amass", "enum", "-passive", "-d", domain]
        output = run_tool(cmd, "SUBDOMAINS/amass")
    else:
        console.print("[bold yellow][SKIP][/bold yellow] [yellow]SUBDOMAINS[/yellow]: Neither 'subfinder' nor 'amass' found.")
        return {"subdomains": []}

    if output is None:
        return {"subdomains": []}

    seen: set[str] = set()
    for line in output.splitlines():
        line = line.strip().lower()
        if line and "." in line and not line.startswith("[") and not line.startswith("#"):
            # Filter out log lines that tools sometimes emit
            if " " not in line:
                if line not in seen:
                    seen.add(line)
                    subdomains.append(line)

    # Always include the root domain itself
    if domain not in seen:
        subdomains.insert(0, domain)

    console.print(f"[bold green][SUBDOMAINS][/bold green] Found {len(subdomains)} subdomains.")
    return {"subdomains": subdomains}
