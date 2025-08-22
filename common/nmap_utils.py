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
        print(port.attrib)
        # Print services
        for service in port.iterfind("service"):
            print(service.attrib)

    # Print os
    print("\nOS Matches:")
    for os in root.iterfind(".//os/osmatch"):
        print(os.attrib)


def scan_ports(target: str):
    # Check if `/opt/homebrew/bin/nmap` exists on macOS
    # TODO: what about other platforms?
    nmap_path = Path("/opt/homebrew/bin/nmap")
    if nmap_path.exists():
        print("Nmap is installed.")
    else:
        # Throw an error to interrupt
        raise FileNotFoundError("Nmap is not installed.")

    password: str = getpass.getpass("Enter your password: ")
    command = f"sudo -S {nmap_path} -oX - -vv -sC -sV -T4 -A {target}"
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
