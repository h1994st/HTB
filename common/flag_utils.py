__all__ = [
    "hide_flag",
]


def hide_flag(flag):
    return flag[:4] + "..." + flag[-5:]
