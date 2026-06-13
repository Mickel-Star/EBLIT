import re
from typing import List


_token_re = re.compile(r"[A-Za-z0-9]+")


def tokenize_identifier(value: str) -> List[str]:
    if value is None:
        return []
    s = str(value)
    s = s.replace("/", " ")
    s = s.replace("\\", " ")
    s = s.replace(":", " ")
    s = s.replace("-", " ")
    s = s.replace("_", " ")
    s = s.replace(".", " ")
    parts = _token_re.findall(s)
    out: List[str] = []
    for p in parts:
        p = p.strip().lower()
        if p:
            out.append(p)
    return out

