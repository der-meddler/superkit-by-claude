"""Change records returned by the mods layer (``apply_mods`` and the per-module editors)."""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Change"]


@dataclass(slots=True)
class Change:
    """One observed/intended modification.

    file    workdir-relative path: ``<part>/<path in partition>`` for tree content, or
            ``<part>/manifest.tsv`` / ``<part>/fs_config`` / ``<part>/file_contexts`` for sidecars.
    op      'fstab' | 'props' | 'add' | 'delete' | 'sidecar' | 'note'
    before  short summary of the previous state (None = did not exist)
    after   short summary of the new state (None = removed)
    detail  optional free text (e.g. the manifest path or key the change refers to)
    """
    file: str
    op: str
    before: str | None
    after: str | None
    detail: str = ""

    def format(self) -> str:
        b = "(absent)" if self.before is None else self.before
        a = "(removed)" if self.after is None else self.after
        d = " [%s]" % self.detail if self.detail else ""
        return "%-7s %s%s\n    - %s\n    + %s" % (self.op, self.file, d, b, a)
