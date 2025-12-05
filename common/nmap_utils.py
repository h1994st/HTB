import getpass
import shlex
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

__all__ = [
    "scan_ports",
]


def _parse_results(outs: str):
    tree = ET.ElementTree(ET.fromstring(outs))
    root = tree.getroot()
    if root is None:
        raise ValueError("Failed to parse XML.")

    # Print ports
    print("Ports:")
    for port in root.iterfind(".//ports/port"):
        # Check state, skip closed ports
        state = port.find("./state")
        if state is None or state.attrib.get("state") != "open":
            continue

        # Print port attributes
        print(port.attrib)

        # Print services
        for service in port.iterfind("service"):
            print(service.attrib)

        # Print scripts
        for script in port.iterfind("script"):
            print(script.attrib)

    # Print os
    print("\nOS Matches:")
    for os in root.iterfind(".//os/osmatch"):
        print(os.attrib)


def scan_ports(target: str, is_udp: bool = False, top_ports: int = 25):
    # Check if `/opt/homebrew/bin/nmap` exists on macOS
    # TODO: what about other platforms?
    nmap_path = Path("/opt/homebrew/bin/nmap")
    if nmap_path.exists():
        print("Nmap is installed.")
    else:
        # Throw an error to interrupt
        raise FileNotFoundError("Nmap is not installed.")

    scan_type = "-sU" if is_udp else "-sC -A"

    password: str = getpass.getpass("Enter your password: ")
    command = f"sudo -S {nmap_path} -oX - -vv {scan_type} -sV -T4 --top-ports {top_ports} {target}"
    process = subprocess.Popen(
        shlex.split(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    outs, errs = process.communicate(input=password + "\n")

    try:
        _parse_results(outs)
    except ValueError as e:
        print(f"Error parsing XML: {e}")
        print(errs)
