#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass
class ResolvedSql:
    source_sql: str
    query_sql: str
    kind: str
    prepared_name: str = ""
    using_vars: List[str] = field(default_factory=list)
    error: str = ""


_PREPARE_RE = re.compile(r"^\s*prepare\s+([A-Za-z0-9_.$]+)\s+from\s+(.+?)\s*$", re.IGNORECASE | re.DOTALL)
_EXECUTE_RE = re.compile(r"^\s*execute\s+([A-Za-z0-9_.$]+)(?:\s+using\s+(.+?))?\s*$", re.IGNORECASE | re.DOTALL)
_DEALLOCATE_RE = re.compile(r"^\s*(?:deallocate\s+prepare|drop\s+prepare)\s+([A-Za-z0-9_.$]+)\s*$", re.IGNORECASE | re.DOTALL)


def _strip_wrapping_quote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        quote = text[0]
        body = text[1:-1]
        if quote == "'":
            body = body.replace("''", "'").replace("\\'", "'")
        elif quote == '"':
            body = body.replace('""', '"').replace('\\"', '"')
        return body
    return text


def _split_using_vars(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_" or ch == "$"


def audit_ps_query_sql(template: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(template):
        ch = template[i]
        if ch in ("'", '"'):
            quote = ch
            out.append("?")
            i += 1
            while i < len(template):
                if template[i] == quote:
                    if i + 1 < len(template) and template[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                if template[i] == "\\" and i + 1 < len(template):
                    i += 2
                    continue
                i += 1
            continue
        if ch.isdigit() and (i == 0 or not _is_ident_char(template[i - 1])):
            j = i + 1
            while j < len(template) and (template[j].isdigit() or template[j] in ".eE+-"):
                if template[j] in "+-" and template[j - 1] not in "eE":
                    break
                j += 1
            if j == len(template) or not _is_ident_char(template[j]):
                out.append("?")
                i = j
                continue
        out.append(ch)
        i += 1
    return "".join(out)


class PsSqlResolver:
    def __init__(self) -> None:
        self.prepared: Dict[str, str] = {}

    def reset(self) -> None:
        self.prepared.clear()

    def consume(self, sql: str) -> Optional[ResolvedSql]:
        prepare = _PREPARE_RE.match(sql)
        if prepare:
            name = prepare.group(1)
            template = _strip_wrapping_quote(prepare.group(2))
            self.prepared[name.lower()] = template
            return ResolvedSql(source_sql=sql, query_sql=sql, kind="prepare", prepared_name=name)

        deallocate = _DEALLOCATE_RE.match(sql)
        if deallocate:
            name = deallocate.group(1)
            self.prepared.pop(name.lower(), None)
            return ResolvedSql(source_sql=sql, query_sql=sql, kind="deallocate", prepared_name=name)

        execute = _EXECUTE_RE.match(sql)
        if execute:
            name = execute.group(1)
            template = self.prepared.get(name.lower(), "")
            if not template:
                return ResolvedSql(
                    source_sql=sql,
                    query_sql="",
                    kind="execute",
                    prepared_name=name,
                    using_vars=_split_using_vars(execute.group(2)),
                    error=f"prepared statement not found: {name}",
                )
            return ResolvedSql(
                source_sql=sql,
                query_sql=audit_ps_query_sql(template),
                kind="execute",
                prepared_name=name,
                using_vars=_split_using_vars(execute.group(2)),
            )

        return ResolvedSql(source_sql=sql, query_sql=sql, kind="normal")


def resolve_workload_sqls(sqls: Iterable[str]) -> List[ResolvedSql]:
    resolver = PsSqlResolver()
    resolved: List[ResolvedSql] = []
    for sql in sqls:
        item = resolver.consume(sql)
        if item is not None:
            resolved.append(item)
    return resolved
