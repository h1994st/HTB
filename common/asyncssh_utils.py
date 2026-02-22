import asyncssh

__all__ = [
    "get_stdout",
]


def get_stdout(result: asyncssh.SSHCompletedProcess) -> str:
    if result.stdout is None:
        return ""
    output = result.stdout
    if isinstance(output, bytes):
        return output.decode()
    elif isinstance(output, str):
        return output
    else:
        raise TypeError(f"Unexpected type for stdout: {type(output)}")
