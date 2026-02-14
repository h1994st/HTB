import re
from typing import Optional

import netifaces
import psutil
from netifaces import InterfaceType
from sh import ErrorReturnCode, grep, lsof  # type: ignore

__all__ = [
    "get_openvpn_utun_ip",
]

OPENVPN_PROCESS_NAME = "OpenVPN Connect"
UTUN_LINE_PATTERN = re.compile(
    r"ctl com.apple.net.utun_control id \d+ unit (?P<utun_num>\d+)"
)


def get_openvpn_utun_ip() -> Optional[str]:
    """
    Get the IP address of the OpenVPN utun interface on macOS.

    :return: IP address of the OpenVPN utun interface
    :rtype: str
    """
    openvpn_process: Optional[psutil.Process] = None
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info["name"] == OPENVPN_PROCESS_NAME:
            openvpn_process = proc
            break
    if openvpn_process is None:
        print("[-] OpenVPN process not found.")
        return None
    print(f"[+] Found OpenVPN process with PID: {openvpn_process.pid}")

    # lsof -p <pid> | grep utun
    try:
        for utun_line in grep(
            "utun", _in=lsof("-p", openvpn_process.pid), _iter=True
        ):
            match = UTUN_LINE_PATTERN.search(utun_line)
            if match is None:
                continue

            utun_num_str = match.group("utun_num")
            utun_num = int(utun_num_str)
            utun_interface = f"utun{utun_num - 1}"

            addrs = netifaces.ifaddresses(utun_interface)
            inet_infos = addrs.get(InterfaceType.AF_INET, None)
            if inet_infos is None:
                continue

            for inet_info in inet_infos:
                ip_addr = inet_info.get("addr", None)
                if ip_addr is None:
                    continue

                print(
                    f"[+] Found OpenVPN utun interface: {utun_interface} with IP: {ip_addr}"
                )
                return ip_addr
    except ErrorReturnCode:
        print("[-] No utun interfaces found for OpenVPN process.")
        return None

    return None


if __name__ == "__main__":
    utun_ifaces = get_openvpn_utun_ip()
    print("Found utun interfaces:", utun_ifaces)
