"""Skill Router + Ops layer absorbed into Easy-Rev.

Inspired by reverse-skill's routing / scope / evidence / field-journal model,
but wired to Easy-Rev runtime (CLI, AI tools, Target Pack).
"""

from easy_rev.skill.case import case_guard, case_init
from easy_rev.skill.evidence import append_evidence, append_finding, append_path
from easy_rev.skill.journal import journal_search, journal_write
from easy_rev.skill.routing import master_route, route_table

__all__ = [
    "master_route",
    "route_table",
    "case_init",
    "case_guard",
    "append_evidence",
    "append_finding",
    "append_path",
    "journal_write",
    "journal_search",
]
