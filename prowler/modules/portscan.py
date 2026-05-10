import xml.etree.ElementTree as ET
from typing import Optional

from rich.console import Console

from prowler.runner import run_tool, tool_exists

console = Console()


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return hosts

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                service_name = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    if product:
                        service_name += f" ({product} {version})".rstrip()

                ports.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": service_name,
                })

        if ports:
            hosts.append({"host": ip, "ports": ports})

    return hosts


def run(targets: list[str], output_dir: str, threads: int = 50, passive: bool = False) -> dict:
    """
    Port scan targets with nmap.
    targets: list of IPs or hostnames
    Returns: {"hosts": [{"host": "1.2.3.4", "ports": [{"port": 80, "service": "http"}]}]}
    """
    if passive:
        console.print("[yellow][PORTSCAN][/yellow] Skipping (--passive mode).")
        return {"hosts": []}

    if not tool_exists("nmap"):
        console.print("[bold yellow][SKIP][/bold yellow] [yellow]PORTSCAN[/yellow]: 'nmap' not found.")
        return {"hosts": []}

    if not targets:
        console.print("[yellow][PORTSCAN][/yellow] No targets to scan.")
        return {"hosts": []}

    cmd = [
        "nmap",
        "-sV",
        "-T4",
        "--open",
        "-oX", "-",  # XML to stdout
    ] + targets

    output = run_tool(cmd, "PORTSCAN/nmap")

    if not output:
        return {"hosts": []}

    # The XML output may be mixed with rich terminal output; extract the XML portion
    xml_start = output.find("<?xml")
    if xml_start == -1:
        # Try to find <nmaprun> directly
        xml_start = output.find("<nmaprun")
    if xml_start == -1:
        console.print("[yellow][PORTSCAN][/yellow] Could not parse nmap XML output.")
        return {"hosts": []}

    xml_data = output[xml_start:]
    hosts = _parse_nmap_xml(xml_data)
    console.print(f"[bold green][PORTSCAN][/bold green] {len(hosts)} hosts with open ports found.")
    return {"hosts": hosts}
