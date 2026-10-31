"""Minimal RFC 8941 Structured Field parsing for RFC 9421 headers.

Parses the Dictionary form used by ``Signature-Input`` and ``Signature``:
members whose value is an Inner List or a Bare Item, each with Parameters.
Raw member text is kept because RFC 9421 §2.3 builds ``@signature-params``
from the signature parameters exactly as received.

Keys are parsed permissively (upper-case letters allowed) so callers can
detect — and report — non-conformant keys such as the reference TAP agent's
``keyId`` instead of failing the whole header.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Any

_KEY_RE = re.compile(r"[A-Za-z*][A-Za-z0-9_\-.*]*")
_TOKEN_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*")
_INT_RE = re.compile(r"-?[0-9]{1,15}")


class SFError(ValueError):
    pass


@dataclass
class Item:
    value: Any
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Member:
    value: Any  # list[Item] for an inner list, else a bare item value
    params: dict[str, Any]
    raw: str  # member text after "key=" (the serialized value + parameters)
    is_inner_list: bool
    nonconformant_keys: list[str] = field(default_factory=list)


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.bad_keys: list[str] = []

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t"):
            self.i += 1

    def key(self) -> str:
        m = _KEY_RE.match(self.s, self.i)
        if not m:
            raise SFError(f"expected key at {self.i}")
        self.i = m.end()
        k = m.group()
        if k != k.lower():
            self.bad_keys.append(k)
        return k

    def bare_item(self) -> Any:
        c = self.peek()
        if c == '"':
            return self.string()
        if c == ":":
            return self.byte_seq()
        if c == "?":
            self.i += 1
            if self.peek() not in ("0", "1"):
                raise SFError("bad boolean")
            self.i += 1
            return self.s[self.i - 1] == "1"
        if c == "-" or c.isdigit():
            m = _INT_RE.match(self.s, self.i)
            if not m:
                raise SFError("bad integer")
            self.i = m.end()
            if self.peek() == ".":
                raise SFError("decimals are not supported here")
            return int(m.group())
        m = _TOKEN_RE.match(self.s, self.i)
        if not m:
            raise SFError(f"unexpected character {c!r} at {self.i}")
        self.i = m.end()
        return m.group()

    def string(self) -> str:
        self.i += 1
        out = []
        while True:
            c = self.peek()
            if c == "":
                raise SFError("unterminated string")
            self.i += 1
            if c == "\\":
                nxt = self.peek()
                if nxt not in ('"', "\\"):
                    raise SFError("bad escape")
                out.append(nxt)
                self.i += 1
            elif c == '"':
                return "".join(out)
            elif not (" " <= c <= "~"):
                raise SFError("non-printable in string")
            else:
                out.append(c)

    def byte_seq(self) -> bytes:
        end = self.s.find(":", self.i + 1)
        if end < 0:
            raise SFError("unterminated byte sequence")
        b64 = self.s[self.i + 1 : end]
        self.i = end + 1
        if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", b64):
            raise SFError("bad byte sequence")
        try:
            return base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
        except binascii.Error as exc:
            raise SFError("bad byte sequence") from exc

    def params(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            k = self.key()
            v: Any = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare_item()
            out[k] = v
        return out

    def inner_list(self) -> list[Item]:
        self.i += 1
        items: list[Item] = []
        while True:
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return items
            v = self.bare_item()
            items.append(Item(v, self.params()))
            if self.peek() not in (" ", ")"):
                raise SFError("bad inner list")

    def dictionary(self) -> dict[str, Member]:
        out: dict[str, Member] = {}
        self.skip_sp()
        while self.i < len(self.s):
            k = self.key()
            bad_before = len(self.bad_keys)
            if self.peek() != "=":
                raise SFError("boolean dictionary members are not supported here")
            self.i += 1
            start = self.i
            if self.peek() == "(":
                val, inner = self.inner_list(), True
            else:
                val, inner = self.bare_item(), False
            params = self.params()
            out[k] = Member(val, params, self.s[start : self.i], inner, self.bad_keys[bad_before:])
            self.skip_ows()
            if self.i >= len(self.s):
                break
            if self.peek() != ",":
                raise SFError(f"expected ',' at {self.i}")
            self.i += 1
            self.skip_ows()
            if self.i >= len(self.s):
                raise SFError("trailing comma")
        return out


def parse_dictionary(text: str) -> dict[str, Member]:
    """Parse an SF Dictionary. Raises SFError on malformed input."""
    if not isinstance(text, str):
        raise SFError("header value must be a string")
    return _Parser(text.strip(" ")).dictionary()
