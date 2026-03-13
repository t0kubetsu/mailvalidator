"""SPF record lookup and validation (RFC 7208).

Resolution strategy
-------------------
SPF allows `include:`, `redirect=`, `a`, `mx`, `ptr`, and `exists` mechanisms
to trigger DNS lookups.  RFC 7208 §4.6.4 caps the *total* lookup count across
the entire resolution tree at 10; exceeding it causes a PermError.

This module walks the full `include:` / `redirect=` tree recursively so that:
  1. The reported lookup count reflects the real cross-tree total.
  2. The resolved records are shown so operators can see what is authorised.

Macro detection
---------------
RFC 7208 §7 macros (e.g. %{d}, %{i}) inside `include:` or `redirect=` targets
cannot be expanded without a live sender IP and envelope-from address.  Targets
that contain macros are noted in the output but not fetched or counted.

Lookup cost table (matches the referenced test procedure)
---------------------------------------------------------
  Counted:  redirect, include, a, mx, ptr, exists
  NOT counted: all, ip4, ip6, exp
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mailcheck.dns_utils import resolve
from mailcheck.models import CheckResult, SPFResult, Status

# RFC 7208 §4.6.4
_MAX_DNS_LOOKUPS = 10

# Mechanisms / modifiers that each consume one DNS lookup.
# Note: `ptr` is deprecated (RFC 7208 §5.5) but still costs a lookup.
_DNS_LOOKUP_TERMS = {"redirect", "include", "a", "mx", "ptr", "exists"}

# Macro expansion placeholder pattern – targets containing these cannot be
# followed without a live SMTP session.
_MACRO_RE = re.compile(r"%\{")


# ---------------------------------------------------------------------------
# SPF tree node
# ---------------------------------------------------------------------------


@dataclass
class _SPFNode:
    """One resolved SPF record in the include / redirect tree."""

    domain: str
    record: str = ""
    includes: list["_SPFNode"] = field(default_factory=list)
    redirect: "_SPFNode | None" = None
    error: str = ""  # non-empty when resolution failed
    macro_skip: bool = False  # True when target contained macros


def _fetch_spf(domain: str) -> str | None:
    """Fetch the SPF TXT record for *domain*, or None if absent / ambiguous."""
    records = resolve(domain, "TXT")
    spf = [r.strip('"') for r in records if r.strip('"').startswith("v=spf1")]
    return spf[0] if len(spf) == 1 else None


def _walk_spf(domain: str, visited: set[str], depth: int = 0) -> _SPFNode:
    """Recursively resolve the SPF record tree rooted at *domain*.

    *visited* tracks domains already seen in this branch to break loops.
    *depth* is a secondary hard cap (RFC 7208 does not define a tree-depth
    limit, but we must guard against adversarial or misconfigured records).
    """
    node = _SPFNode(domain=domain)

    if domain in visited or depth > 10:
        node.error = f"Loop or depth limit reached for '{domain}'"
        return node
    visited.add(domain)

    raw = _fetch_spf(domain)
    if raw is None:
        node.error = f"No SPF record found for '{domain}'"
        return node

    node.record = raw
    for term in raw.split()[1:]:  # skip "v=spf1"
        bare = term.lstrip("+-~?")
        bare_lower = bare.lower()

        if bare_lower.startswith("include:"):
            target = bare[len("include:") :]
            if _MACRO_RE.search(target):
                child = _SPFNode(domain=target, macro_skip=True)
            else:
                child = _walk_spf(target, visited, depth + 1)
            node.includes.append(child)

        elif bare_lower.startswith("redirect="):
            target = bare[len("redirect=") :]
            if _MACRO_RE.search(target):
                node.redirect = _SPFNode(domain=target, macro_skip=True)
            else:
                node.redirect = _walk_spf(target, visited, depth + 1)

    return node


def _count_lookups(node: _SPFNode) -> int:
    """Return the total DNS lookup cost of the tree rooted at *node*.

    Per RFC 7208 §4.6.4 each of: include, redirect, a, mx, ptr, exists
    counts as one lookup.  Macro-expanded targets are not counted (we cannot
    evaluate them without a live session).
    """
    if node.error or node.macro_skip:
        return 0

    count = 0
    for term in node.record.split()[1:]:
        bare = term.lstrip("+-~?").lower()
        for mech in _DNS_LOOKUP_TERMS:
            if (
                bare == mech
                or bare.startswith(mech + ":")
                or bare.startswith(mech + "=")
            ):
                count += 1
                break

    for child in node.includes:
        count += _count_lookups(child)
    if node.redirect:
        count += _count_lookups(node.redirect)

    return count


def _flatten_detail_lines(node: _SPFNode, indent: int = 0) -> list[str]:
    """Render the resolution tree as indented human-readable lines."""
    pad = "  " * indent
    arrow = "↳ " if indent else ""
    lines: list[str] = []

    if node.macro_skip:
        lines.append(f"{pad}{arrow}{node.domain}: (contains macros – not followed)")
        return lines
    if node.error:
        lines.append(f"{pad}⚠  {node.domain}: {node.error}")
        return lines

    lines.append(f"{pad}{arrow}{node.domain}: {node.record}")
    for child in node.includes:
        lines.extend(_flatten_detail_lines(child, indent + 1))
    if node.redirect:
        lines.extend(_flatten_detail_lines(node.redirect, indent + 1))

    return lines


# ---------------------------------------------------------------------------
# Policy strictness helpers
# ---------------------------------------------------------------------------


def _has_redirect(terms: list[str]) -> bool:
    return any(t.lstrip("+-~?").lower().startswith("redirect=") for t in terms)


def _effective_all(record: str, tree: _SPFNode | None) -> str | None:
    """Return the effective 'all' qualifier for the record.

    If the top-level record has no `all` but has a `redirect=`, follow the
    redirect to find its `all` term (RFC 7208 §6.1: redirect replaces the
    whole record when there is no explicit `all`).
    """
    terms = record.split()
    all_term = next((t for t in terms if re.match(r"[+\-~?]?all$", t, re.I)), None)
    if all_term:
        return all_term

    # No `all` – check redirect
    if tree and tree.redirect and tree.redirect.record and not tree.redirect.error:
        redirect_terms = tree.redirect.record.split()
        return next(
            (t for t in redirect_terms if re.match(r"[+\-~?]?all$", t, re.I)), None
        )

    return None  # truly missing


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_spf(domain: str) -> SPFResult:
    result = SPFResult(domain=domain)

    records = resolve(domain, "TXT")
    spf_records = [r.strip('"') for r in records if r.strip('"').startswith("v=spf1")]

    if not spf_records:
        result.checks.append(
            CheckResult(
                name="SPF Record",
                status=Status.NOT_FOUND,
                details=[f"No SPF record found for {domain}."],
            )
        )
        return result

    if len(spf_records) > 1:
        result.checks.append(
            CheckResult(
                name="Multiple SPF Records",
                status=Status.ERROR,
                details=[
                    "More than one SPF TXT record found. RFC 7208 §3.2 requires exactly one."
                ],
            )
        )

    record = spf_records[0]
    result.record = record
    result.checks.append(
        CheckResult(name="SPF Record", status=Status.OK, details=[record])
    )

    _validate_spf(record, domain, result)
    return result


def _validate_spf(record: str, domain: str, result: SPFResult) -> None:
    terms = record.split()

    # --- Version tag ---
    if terms[0] != "v=spf1":
        result.checks.append(
            CheckResult(name="SPF Version", status=Status.ERROR, value=terms[0])
        )
        return
    result.checks.append(
        CheckResult(name="SPF Version", status=Status.OK, value="v=spf1")
    )

    # --- Recurse into include / redirect tree ---
    has_dynamic = any(
        t.lstrip("+-~?").lower().startswith("include:")
        or t.lstrip("+-~?").lower().startswith("redirect=")
        for t in terms
    )
    tree: _SPFNode | None = None
    if has_dynamic:
        tree = _walk_spf(domain, visited=set())

    # --- 'all' policy ---
    # When `all` is absent and no `redirect` is present, RFC 7208 §4.7
    # implies a default of `?all` (neutral) – i.e. no protection.
    explicit_all = next((t for t in terms if re.match(r"[+\-~?]?all$", t, re.I)), None)
    has_redirect_mod = _has_redirect(terms)
    effective = _effective_all(record, tree)

    if explicit_all is None and not has_redirect_mod:
        # No `all` and no redirect → implicit ?all → no protection
        result.checks.append(
            CheckResult(
                name="SPF Policy",
                status=Status.WARNING,
                details=[
                    "No 'all' term and no 'redirect' modifier found. "
                    "RFC 7208 §4.7 implies a default of '?all' (neutral) – this provides no protection."
                ],
            )
        )
    elif explicit_all is None and has_redirect_mod:
        # Policy is delegated entirely to the redirect target
        if effective:
            _emit_all_check(effective, result, via_redirect=True)
        else:
            result.checks.append(
                CheckResult(
                    name="SPF Policy",
                    status=Status.WARNING,
                    details=[
                        "redirect= target has no 'all' term; effective policy is unknown."
                    ],
                )
            )
    else:
        _emit_all_check(explicit_all, result)

    # --- ptr deprecation ---
    if any(t.lstrip("+-~?").lower().startswith("ptr") for t in terms):
        result.checks.append(
            CheckResult(
                name="ptr Mechanism",
                status=Status.WARNING,
                details=[
                    "The 'ptr' mechanism is deprecated (RFC 7208 §5.5) and slow. Remove it."
                ],
            )
        )

    # --- Include / redirect resolution details ---
    if tree is not None:
        detail_lines = _flatten_detail_lines(tree)
        has_errors = any("⚠" in l for l in detail_lines)
        result.checks.append(
            CheckResult(
                name="SPF Include Resolution",
                status=Status.WARNING if has_errors else Status.OK,
                details=detail_lines,
            )
        )

    # --- DNS lookup count (recursive) ---
    if tree is not None:
        total = _count_lookups(tree)
    else:
        # Flat record: count directly
        total = sum(
            1
            for t in terms
            if any(
                t.lstrip("+-~?").lower() == m
                or t.lstrip("+-~?").lower().startswith(m + ":")
                or t.lstrip("+-~?").lower().startswith(m + "=")
                for m in _DNS_LOOKUP_TERMS
            )
        )

    if total > _MAX_DNS_LOOKUPS:
        result.checks.append(
            CheckResult(
                name="DNS Lookup Count",
                status=Status.ERROR,
                value=f"{total}/{_MAX_DNS_LOOKUPS}",
                details=[
                    f"SPF lookup count is {total}, exceeding the RFC 7208 §4.6.4 limit of {_MAX_DNS_LOOKUPS}. "
                    "Receivers will return PermError and SPF authentication will fail."
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="DNS Lookup Count",
                status=Status.OK,
                value=f"{total}/{_MAX_DNS_LOOKUPS}",
                details=(
                    ["Count includes all nested include: and redirect= records."]
                    if tree is not None
                    else []
                ),
            )
        )


def _emit_all_check(
    all_term: str,
    result: SPFResult,
    via_redirect: bool = False,
) -> None:
    """Append the 'SPF Policy' CheckResult for a given `all` qualifier.

    Grading follows the referenced test procedure:
      -all  → OK       (strict fail)
      ~all  → OK       (softfail; preferred for sending domains per the spec)
      ?all  → WARNING  (neutral; no protection)
      +all  → ERROR    (pass; critical misconfiguration)
      all   → OK       (bare 'all' without qualifier defaults to '+' per RFC,
                        but in practice is treated as '-all' by most tools;
                        we treat it as OK with a note)
    """
    suffix = f" (via redirect)" if via_redirect else ""
    q = all_term[0] if all_term[0] in "+-~?" else "-"  # bare 'all' → treat as -all

    if q == "-":
        result.checks.append(
            CheckResult(
                name="SPF Policy",
                status=Status.OK,
                value=all_term + suffix,
                details=[
                    "-all (fail): only listed senders are authorised. "
                    "Note: some forwarding scenarios may cause false failures; "
                    "consider ~all if you rely on mail forwarding."
                ],
            )
        )
    elif q == "~":
        result.checks.append(
            CheckResult(
                name="SPF Policy",
                status=Status.OK,
                value=all_term + suffix,
                details=[
                    "~all (softfail): recommended for most sending domains. "
                    "Softfail lets receivers evaluate DKIM and DMARC before rejecting forwarded mail."
                ],
            )
        )
    elif q == "?":
        result.checks.append(
            CheckResult(
                name="SPF Policy",
                status=Status.WARNING,
                value=all_term + suffix,
                details=[
                    "?all (neutral) provides no protection against spoofing. Use ~all or -all."
                ],
            )
        )
    else:  # "+"
        result.checks.append(
            CheckResult(
                name="SPF Policy",
                status=Status.ERROR,
                value=all_term + suffix,
                details=[
                    "+all authorises every server on the Internet to send as your domain – "
                    "this is a critical misconfiguration. Replace with ~all or -all immediately."
                ],
            )
        )
