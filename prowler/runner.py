import shutil
import subprocess
import threading
from typing import Optional

from rich.console import Console

console = Console()


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_tool(cmd: list[str], label: str) -> Optional[str]:
    """
    Run a subprocess, stream stdout/stderr live to terminal with a colored label prefix,
    capture and return combined output. Returns None if the tool is not found.
    """
    tool_name = cmd[0]
    if not tool_exists(tool_name):
        console.print(f"[bold yellow][SKIP][/bold yellow] [yellow]{label}[/yellow]: '{tool_name}' not found — install it to enable this module.")
        return None

    console.print(f"\n[bold cyan][{label}][/bold cyan] Running: [dim]{' '.join(cmd)}[/dim]")

    captured_lines: list[str] = []
    lock = threading.Lock()

    def stream_fd(fd, color: str):
        for raw in iter(fd.readline, b""):
            line = raw.decode(errors="replace").rstrip("\n")
            with lock:
                captured_lines.append(line)
            console.print(f"[{color}][{label}][/{color}] {line}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        t_out = threading.Thread(target=stream_fd, args=(proc.stdout, "green"), daemon=True)
        t_err = threading.Thread(target=stream_fd, args=(proc.stderr, "yellow"), daemon=True)
        t_out.start()
        t_err.start()

        proc.wait()
        t_out.join()
        t_err.join()

        if proc.returncode != 0:
            console.print(f"[bold yellow][{label}][/bold yellow] Exited with code {proc.returncode}")

        return "\n".join(captured_lines)

    except FileNotFoundError:
        console.print(f"[bold yellow][SKIP][/bold yellow] [yellow]{label}[/yellow]: '{tool_name}' not found — install it to enable this module.")
        return None
    except Exception as exc:
        console.print(f"[bold red][ERROR][/bold red] [{label}]: {exc}")
        return None
