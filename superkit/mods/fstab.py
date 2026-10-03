"""Android fstab editing that preserves everything it does not touch.

An fstab line is ``<src> <mount point> <fs type> <mount options> <fs_mgr flags>`` with
fields separated by runs of tabs/spaces.  Samsung/MTK files mix tabs and spaces and leave
empty tokens in the comma lists (``wait,,avb,logical``); comments, blank lines, the
original separators and those empty tokens are all preserved.  Only lines with at least
five fields are entries; everything else is passed through verbatim.

Token patterns are glob-style (``fnmatch``): ``avb`` matches only the exact token,
``avb=*`` matches ``avb=vbmeta_system`` but not ``avb``; empty tokens never match.
When a list loses all its tokens it becomes ``defaults``.

Line-level API (``str`` in, ``str`` out, line ending kept):
    remove_flags(line, patterns) / add_flags(line, tokens)
    remove_mount_options(line, patterns) / add_mount_options(line, tokens)
    set_fs_type(line, fstype)
File-level API: ``edit_fstab(text, mount_points, ...)`` applies the same operations to
every entry whose mount point is in ``mount_points`` (all fs-type variants of a mount
point, e.g. the three ``/system`` lines, are matched).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "FstabLine", "parse_line", "parse_fstab", "format_fstab",
    "remove_flags", "add_flags", "remove_mount_options", "add_mount_options", "set_fs_type",
    "edit_fstab", "entries_for", "split_tokens", "join_tokens",
    "FIELD_SRC", "FIELD_MNT", "FIELD_FSTYPE", "FIELD_MNT_OPTS", "FIELD_FLAGS",
]

FIELD_SRC, FIELD_MNT, FIELD_FSTYPE, FIELD_MNT_OPTS, FIELD_FLAGS = range(5)
_MIN_FIELDS = 5

_EOL_RE = re.compile(r"(\r\n|\n|\r)?$")
_FRAME_RE = re.compile(r"^(\s*)(.*?)(\s*)$", re.S)
_SEP_RE = re.compile(r"(\s+)")


@dataclass(slots=True)
class FstabLine:
    """One line.  ``fields`` is empty for comments/blank/short lines (``raw`` is used)."""
    raw: str                      # original line body (no line ending)
    eol: str                      # '', '\n' or '\r\n'
    lead: str = ""                # leading whitespace
    fields: list[str] = field(default_factory=list)
    seps: list[str] = field(default_factory=list)   # separators between fields (len = len(fields)-1)
    trail: str = ""               # trailing whitespace

    @property
    def is_entry(self) -> bool:
        return len(self.fields) >= _MIN_FIELDS

    @property
    def mount_point(self) -> str | None:
        return self.fields[FIELD_MNT] if self.is_entry else None

    def format(self) -> str:
        if not self.is_entry:
            return self.raw + self.eol
        out = [self.lead]
        for i, f in enumerate(self.fields):
            if i:
                out.append(self.seps[i - 1])
            out.append(f)
        out.append(self.trail)
        out.append(self.eol)
        return "".join(out)


def parse_line(line: str) -> FstabLine:
    """Parse one line (with or without its line ending)."""
    m = _EOL_RE.search(line)
    eol = m.group(1) or ""
    body = line[: m.start()] if eol else line
    fl = FstabLine(raw=body, eol=eol)
    stripped = body.strip()
    if not stripped or stripped.startswith("#"):
        return fl
    lead, core, trail = _FRAME_RE.match(body).groups()
    parts = _SEP_RE.split(core)
    fields = parts[0::2]
    seps = parts[1::2]
    if len(fields) < _MIN_FIELDS:
        return fl
    fl.lead, fl.fields, fl.seps, fl.trail = lead, fields, seps, trail
    return fl


def parse_fstab(text: str) -> list[FstabLine]:
    return [parse_line(l) for l in text.splitlines(keepends=True)]


def format_fstab(lines: Iterable[FstabLine]) -> str:
    return "".join(l.format() for l in lines)


# --------------------------------------------------------------------------- tokens

def split_tokens(s: str) -> list[str]:
    return s.split(",")


def join_tokens(tokens: Sequence[str]) -> str:
    if not any(tokens):
        return "defaults"
    return ",".join(tokens)


def _matches(token: str, patterns: Sequence[str]) -> bool:
    if token == "":
        return False
    return any(fnmatch.fnmatchcase(token, p) for p in patterns)


def _remove_tokens(s: str, patterns: Sequence[str]) -> str:
    patterns = list(patterns)
    if not patterns:
        return s
    kept = [t for t in split_tokens(s) if not _matches(t, patterns)]
    return join_tokens(kept)


def _add_tokens(s: str, tokens: Sequence[str]) -> str:
    tokens = list(tokens)
    if not tokens:
        return s
    cur = split_tokens(s)
    if cur == ["defaults"]:
        cur = []
    for t in tokens:
        if not t or "," in t or any(c.isspace() for c in t):
            raise ValueError("bad fstab token %r" % t)
        if t in cur:
            continue
        key = t.split("=", 1)[0] if "=" in t else None
        if key is not None:
            for i, x in enumerate(cur):
                if "=" in x and x.split("=", 1)[0] == key:
                    cur[i] = t
                    break
            else:
                cur.append(t)
        else:
            cur.append(t)
    return join_tokens(cur)


def _edit_field(line: str | FstabLine, idx: int, fn) -> str | FstabLine:
    fl = parse_line(line) if isinstance(line, str) else line
    if fl.is_entry:
        fl.fields[idx] = fn(fl.fields[idx])
    return fl.format() if isinstance(line, str) else fl


def remove_flags(line, patterns: Sequence[str]):
    """Remove fs_mgr flags (5th field) matching any glob pattern."""
    return _edit_field(line, FIELD_FLAGS, lambda s: _remove_tokens(s, patterns))


def add_flags(line, tokens: Sequence[str]):
    """Add fs_mgr flags (exact tokens; ``key=value`` replaces an existing ``key=...``)."""
    return _edit_field(line, FIELD_FLAGS, lambda s: _add_tokens(s, tokens))


def remove_mount_options(line, patterns: Sequence[str]):
    """Remove mount options (4th field) matching any glob pattern."""
    return _edit_field(line, FIELD_MNT_OPTS, lambda s: _remove_tokens(s, patterns))


def add_mount_options(line, tokens: Sequence[str]):
    return _edit_field(line, FIELD_MNT_OPTS, lambda s: _add_tokens(s, tokens))


def set_fs_type(line, fstype: str):
    if not fstype or any(c.isspace() for c in fstype):
        raise ValueError("bad fs type %r" % fstype)
    return _edit_field(line, FIELD_FSTYPE, lambda s: fstype)


# --------------------------------------------------------------------------- file level

def entries_for(lines: Iterable[FstabLine], mount_points: Iterable[str]) -> list[FstabLine]:
    mps = set(mount_points)
    return [l for l in lines if l.is_entry and l.mount_point in mps]


def edit_fstab(text: str, mount_points: Iterable[str], *,
               remove_flags_: Sequence[str] = (), add_flags_: Sequence[str] = (),
               remove_mount_options_: Sequence[str] = (), add_mount_options_: Sequence[str] = (),
               fs_type: str | None = None, require_match: bool = False) -> str:
    """Apply the operations to every entry mounted at one of ``mount_points``.

    Order per entry: remove flags, add flags, remove mount options, add mount options,
    set fs type.  Returns the new text (identical to ``text`` when nothing changed).
    With ``require_match`` a ValueError is raised when no entry matched.
    """
    lines = parse_fstab(text)
    selected = entries_for(lines, mount_points)
    if require_match and not selected:
        raise ValueError("no fstab entry mounted at %s" % ", ".join(sorted(set(mount_points))))
    for fl in selected:
        if remove_flags_:
            remove_flags(fl, remove_flags_)
        if add_flags_:
            add_flags(fl, add_flags_)
        if remove_mount_options_:
            remove_mount_options(fl, remove_mount_options_)
        if add_mount_options_:
            add_mount_options(fl, add_mount_options_)
        if fs_type:
            set_fs_type(fl, fs_type)
    return format_fstab(lines)
