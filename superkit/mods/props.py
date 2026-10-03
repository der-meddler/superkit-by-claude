"""build.prop-style editing that preserves order, comments, blank lines and ``import`` lines.

Android property files (``init`` ``LoadProperties``): ``key=value`` sets, ``key?=value``
sets only when unset, ``import <file>`` includes another file, ``#`` starts a comment.
Keys and values are kept verbatim; edited/new lines are written as ``key=value``.

* ``set``     – rewrite every ``key=`` line of the key (``?=`` lines are left alone, an
                unconditional ``=`` always wins over them); a missing key is appended at
                the end of the file, or right after the last line of the ``after`` key.
* ``remove``  – drop every ``key=`` and ``key?=`` line of the key (comments untouched).
* ``append``  – add ``value`` to the comma-separated (``separator``) value of ``key``
                if it is not already an element; a missing key is created.
All operations are idempotent and return the text unchanged when nothing has to change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

__all__ = [
    "PropLine", "parse_props", "format_props", "get_prop", "get_props",
    "set_props", "remove_props", "append_props", "edit_props", "format_value",
]

_EOL_RE = re.compile(r"(\r\n|\n|\r)?$")
_PROP_RE = re.compile(r"^(\s*)([^\s#=?][^=?]*?)\s*(\?=|=)(.*)$", re.S)
_IMPORT_RE = re.compile(r"^\s*import\s+\S")


@dataclass(slots=True)
class PropLine:
    kind: str                 # 'prop' | 'comment' | 'blank' | 'import' | 'other'
    raw: str                  # body without line ending
    eol: str
    key: str | None = None
    op: str | None = None     # '=' or '?='
    value: str | None = None

    def format(self) -> str:
        return self.raw + self.eol


def _make_prop(key: str, value: str, eol: str) -> PropLine:
    return PropLine("prop", "%s=%s" % (key, value), eol, key, "=", value)


def parse_props(text: str) -> list[PropLine]:
    out = []
    for line in text.splitlines(keepends=True):
        m = _EOL_RE.search(line)
        eol = m.group(1) or ""
        body = line[: m.start()] if eol else line
        s = body.strip()
        if not s:
            out.append(PropLine("blank", body, eol))
        elif s.startswith("#"):
            out.append(PropLine("comment", body, eol))
        elif _IMPORT_RE.match(body):
            out.append(PropLine("import", body, eol))
        else:
            pm = _PROP_RE.match(body)
            if pm:
                _, key, op, value = pm.groups()
                out.append(PropLine("prop", body, eol, key, op, value.strip()))
            else:
                out.append(PropLine("other", body, eol))
    return out


def format_props(lines: Iterable[PropLine]) -> str:
    return "".join(l.format() for l in lines)


def get_props(text: str) -> dict[str, str]:
    """Effective ``key -> value`` of unconditional ``=`` lines (later wins), ``?=`` only if unset."""
    out: dict[str, str] = {}
    cond: dict[str, str] = {}
    for l in parse_props(text):
        if l.kind != "prop":
            continue
        if l.op == "=":
            out[l.key] = l.value
        elif l.key not in cond:
            cond[l.key] = l.value
    for k, v in cond.items():
        out.setdefault(k, v)
    return out


def get_prop(text: str, key: str) -> str | None:
    return get_props(text).get(key)


def format_value(v) -> str:
    """TOML scalar -> property value text (bools as true/false)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float, str)):
        return str(v)
    raise ValueError("unsupported property value %r" % (v,))


def _check_key(key: str) -> None:
    if not key or any(c.isspace() for c in key) or "=" in key or "?" in key or key.startswith("#"):
        raise ValueError("bad property key %r" % key)


def _check_value(value: str) -> None:
    if "\n" in value or "\r" in value:
        raise ValueError("property value may not contain newlines: %r" % value)


def _eol_of(lines: list[PropLine]) -> str:
    for l in lines:
        if l.eol:
            return l.eol
    return "\n"


def _fix_last_eol(lines: list[PropLine], eol: str) -> None:
    if lines and not lines[-1].eol:
        lines[-1].eol = eol


def _insert_new(lines: list[PropLine], new: list[PropLine], after: str | None) -> None:
    if not new:
        return
    eol = _eol_of(lines)
    for l in new:
        l.eol = eol
    if after is None:
        _fix_last_eol(lines, eol)
        lines.extend(new)
        return
    _check_key(after)
    pos = None
    for i, l in enumerate(lines):
        if l.kind == "prop" and l.key == after:
            pos = i
    if pos is None:
        raise ValueError("anchor key %r not found" % after)
    if not lines[pos].eol:
        lines[pos].eol = eol
    lines[pos + 1:pos + 1] = new


def set_props(text: str, values: Mapping[str, object], after: str | None = None) -> str:
    lines = parse_props(text)
    new: list[PropLine] = []
    for key, v in values.items():
        _check_key(key)
        value = format_value(v)
        _check_value(value)
        found = False
        for l in lines:
            if l.kind == "prop" and l.key == key and l.op == "=":
                found = True
                if l.value != value or l.raw != "%s=%s" % (key, value):
                    l.raw, l.value = "%s=%s" % (key, value), value
        if not found:
            new.append(_make_prop(key, value, ""))
    _insert_new(lines, new, after)
    return format_props(lines)


def remove_props(text: str, keys: Iterable[str]) -> str:
    keys = set(keys)
    for k in keys:
        _check_key(k)
    lines = parse_props(text)
    kept = [l for l in lines if not (l.kind == "prop" and l.key in keys)]
    if len(kept) == len(lines):
        return text
    return format_props(kept)


def append_props(text: str, values: Mapping[str, object], separator: str = ",",
                 after: str | None = None) -> str:
    if not separator:
        raise ValueError("separator must not be empty")
    lines = parse_props(text)
    new: list[PropLine] = []
    for key, v in values.items():
        _check_key(key)
        value = format_value(v)
        _check_value(value)
        targets = [l for l in lines if l.kind == "prop" and l.key == key and l.op == "="]
        if not targets:
            new.append(_make_prop(key, value, ""))
            continue
        for l in targets:
            parts = l.value.split(separator) if l.value else []
            if value in parts:
                continue
            parts.append(value)
            l.value = separator.join(parts)
            l.raw = "%s=%s" % (key, l.value)
    _insert_new(lines, new, after)
    return format_props(lines)


def edit_props(text: str, *, set: Mapping[str, object] | None = None,
               remove: Sequence[str] = (), append: Mapping[str, object] | None = None,
               separator: str = ",", after: str | None = None) -> str:
    """remove, then set, then append (so a key can be removed and re-added in one step)."""
    if remove:
        text = remove_props(text, remove)
    if set:
        text = set_props(text, set, after)
    if append:
        text = append_props(text, append, separator, after)
    return text
