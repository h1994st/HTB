from pathlib import Path

from sh import hashcat  # type: ignore

__all__ = ["crack_hashes"]


def crack_hashes(
    input_file: Path,
    wordlist: Path,
    hash_mode: str,
    username: bool = False,
) -> str:
    """
    Crack password hashes using hashcat.

    Args:
        input_file (Path): Path to the input file containing password hashes.
        wordlist (Path): Path to the wordlist file.
        hash_mode (str): The hash mode to use.
        username (bool): Whether the input file contains usernames (default: False).
    """
    # Define the hashcat command
    hashcat_cmd = []
    if username:
        hashcat_cmd.append("--username")  # Include this option if usernames are present
    hashcat_cmd += [
        "-m",
        hash_mode,  # Hash type
        "-a",
        "0",  # Attack mode (0 for straight)
        input_file,
        wordlist.resolve(),  # Wordlist path
        "--force",  # Force execution even if warnings are present
    ]

    # Execute the hashcat command
    try:
        hashcat(*hashcat_cmd)

        # Print the cracked hashes to the console
        output = hashcat("--show", *hashcat_cmd[:-2])
        return output.strip()
    except Exception as e:
        return ""
