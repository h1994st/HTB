import json

__all__ = [
    "parse_ffuf_json",
]


def parse_ffuf_json(file_path: str) -> list[str]:
    with open(file_path, "r") as fp:
        ffuf_output = json.load(fp)

    if len(ffuf_output["results"]) == 0:
        print("[-] No results found in FFUF output.")
        return []

    new_hosts: list[str] = []
    print(f"[+] FFUF output ({len(ffuf_output['results'])} in total):")
    for entry in ffuf_output["results"]:
        print(f"[+] - {entry['input']['FUZZ']}: {entry['host']}")
        new_hosts.append(entry["host"])

    return new_hosts
