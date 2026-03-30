"""SPF record lookup and validation (RFC 7208).

Resolution strategy
-------------------
SPF allows `include:`, `redirect=`, `a`, `mx`, `ptr`, and `exists` mechanisms
to trigger DNS lookups.  RFC 7208 §4.6.4 caps the *total* lookup count across
the entire resolution tree at 10; exceeding it causes a PermError.  The same
section (as clarified by errata and universally deployed by receivers) also
caps *void lookups* — lookups that return an empty answer or NXDOMAIN — at 2.

This module walks the full `include:` / `redirect=` tree recursively so that:
  1. The reported lookup count reflects the real cross-tree total.
  2. Void lookups are counted separately and flagged when they exceed 2.
  3. The resolved records are shown so operators can see what is authorised.

Lookup counting details
-----------------------
  Counted toward the 10-lookup limit:
    redirect, include, a, mx, ptr, exists

  NOT counted: all, ip4, ip6, exp

  The `a` mechanism (and variants `a/cidr`, `a:domain/cidr4/cidr6`) is
  detected by prefix matching to handle CIDR suffixes correctly.  A plain
  `a/24` or `a:mail.example.com/24` therefore counts as expected.

  Void lookup limit (RFC 7208 §4.6.4):
    DNS lookups that return an empty answer set (no records / NXDOMAIN) count
    toward a separate limit of 2.  Receivers treat exceeding this as a
    PermError, just like the 10-lookup limit.  Macro-expanded targets and
    error nodes are not counted here.

Macro detection
---------------
RFC 7208 §7 macros (e.g. %{d}, %{i}) inside `include:` or `redirect=` targets
cannot be expanded without a live sender IP and envelope-from address.  Targets
that contain macros are noted in the output but not fetched or counted.

include: qualifier surfacing
-----------------------------
RFC 7208 §5.2: when an include: target matches, the *qualifier* on the
include: mechanism in the parent record (default +, or explicitly -, ~, ?)
determines the final result — not the included record's own `all` term.
A `-include:foo` means a match inside foo.com's record returns Fail for the
parent, not Pass.  The qualifier is surfaced in the resolution tree output so
operators can audit it.

Nested +all warning
-------------------
An included record that ends with `+all` (or bare `all`) effectively
authorises every host on the Internet to match that include:, meaning the
parent can Pass any sender.  Even if the top-level record ends with `-all`,
the `+all` inside an include: is a security hazard and is flagged.

exp= modifier
-------------
The `exp=` modifier (RFC 7208 §6.2) specifies an explanation TXT record
returned to senders on Fail.  It is correctly not counted as a DNS lookup
(the lookup happens at evaluation time, not check time), but it is surfaced
in the output for operator awareness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, SPFResult, Status

# RFC 7208 §4.6.4
_MAX_DNS_LOOKUPS = 10
_MAX_VOID_LOOKUPS = 2

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
    qualifier: str = "+"  # qualifier on the include: that led here
    includes: list["_SPFNode"] = field(default_factory=list)
    redirect: "_SPFNode | None" = None
    error: str = ""  # non-empty when resolution failed
    macro_skip: bool = False  # True when target contained macros
    void: bool = False  # True when DNS returned no records


def _fetch_spf(domain: str) -> str | None:
    """Fetch the SPF TXT record for *domain*, or ``None`` if absent or ambiguous.

    :param domain: Domain to fetch the SPF record for.
    :returns: The raw SPF TXT string, or ``None`` if no unambiguous record
        was found.
    :rtype: str | None
    """
    records = resolve(domain, "TXT")
    spf = [r.strip('"') for r in records if r.strip('"').startswith("v=spf1")]
    return spf[0] if len(spf) == 1 else None


def _walk_spf(
    domain: str,
    visited: set[str],
    depth: int = 0,
    qualifier: str = "+",
) -> _SPFNode:
    """Recursively resolve the SPF record tree rooted at *domain*.

    *visited* is a **per-branch** copy; each call site must pass
    ``visited.copy()`` when forking into a new include or redirect so that a
    domain referenced from two independent include: chains is not wrongly
    treated as a loop.  Only a true cycle on the *same* path is blocked.

    *depth* is a secondary hard cap (RFC 7208 does not define a tree-depth
    limit, but we must guard against adversarial or misconfigured records).

    :param domain: Domain name to resolve.
    :type domain: str
    :param visited: Set of domain names already visited on this branch.
    :type visited: set[str]
    :param depth: Current recursion depth (internal; starts at 0).
    :type depth: int
    :param qualifier: The qualifier character (+, -, ~, ?) from the parent
        include: term that led to this node.
    :type qualifier: str
    :returns: Populated SPF tree node.
    :rtype: _SPFNode
    """
    node = _SPFNode(domain=domain, qualifier=qualifier)

    if domain in visited or depth > 10:
        node.error = f"Loop or depth limit reached for '{domain}'"
        return node
    visited = visited | {domain}  # immutable update — does not affect siblings

    raw = _fetch_spf(domain)
    if raw is None:
        node.error = f"No SPF record found for '{domain}'"
        node.void = True
        return node

    node.record = raw
    for term in raw.split()[1:]:  # skip "v=spf1"
        # Peel the qualifier before inspecting the mechanism name.
        q = term[0] if term[0] in "+-~?" else "+"
        bare = term.lstrip("+-~?")
        bare_lower = bare.lower()

        if bare_lower.startswith("include:"):
            target = bare[len("include:") :]
            if _MACRO_RE.search(target):
                child = _SPFNode(domain=target, macro_skip=True, qualifier=q)
            else:
                child = _walk_spf(target, visited, depth + 1, qualifier=q)
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

    Per RFC 7208 §4.6.4 each of: ``include``, ``redirect``, ``a``, ``mx``,
    ``ptr``, ``exists`` counts as one lookup.  Macro-expanded targets and
    error nodes contribute 0 (they were not resolved).

    The ``a`` mechanism is matched by prefix so that ``a/24`` and
    ``a:mail.example.com/24`` are correctly counted alongside plain ``a``
    and ``a:domain``.

    :param node: Root of the SPF resolution tree.
    :type node: _SPFNode
    :returns: Total number of DNS lookups in this tree.
    :rtype: int
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
                or bare.startswith(mech + "/")  # e.g. a/24, mx/24
            ):
                count += 1
                break

    for child in node.includes:
        count += _count_lookups(child)
    if node.redirect:
        count += _count_lookups(node.redirect)

    return count


def _count_void_lookups(node: _SPFNode) -> int:
    """Return the number of void (empty-answer) DNS lookups in the tree.

    Per RFC 7208 §4.6.4 a lookup that returns no records (NXDOMAIN or empty
    answer set) counts toward a separate limit of 2.  Exceeding it causes a
    PermError at receivers.

    :param node: Root of the SPF resolution tree.
    :type node: _SPFNode
    :returns: Number of void lookups.
    :rtype: int
    """
    if node.macro_skip:
        return 0
    count = 1 if node.void else 0
    for child in node.includes:
        count += _count_void_lookups(child)
    if node.redirect:
        count += _count_void_lookups(node.redirect)
    return count


def _has_nested_plus_all(node: _SPFNode) -> bool:
    """Return ``True`` if any *included* record in the tree ends with ``+all``.

    An included record that matches ``+all`` means every host in the world
    passes that include:, which is a security hazard regardless of the
    top-level ``all`` qualifier.  ``redirect=`` targets are not checked here
    because a redirect *replaces* the whole record — that is caught by the
    top-level ``all`` grading.

    :param node: Root of the SPF resolution tree.
    :type node: _SPFNode
    :returns: ``True`` when a nested include: record contains ``+all``.
    :rtype: bool
    """
    for child in node.includes:
        if child.macro_skip or child.error:
            continue
        terms = child.record.split()
        all_term = next((t for t in terms if re.match(r"[+]?all$", t, re.I)), None)
        if all_term is not None:
            # bare 'all' and '+all' both mean Pass
            return True
        if _has_nested_plus_all(child):
            return True
    return False


def _flatten_detail_lines(node: _SPFNode, indent: int = 0) -> list[str]:
    """Render the resolution tree as indented human-readable lines.

    The qualifier on include: terms is shown so operators can audit how a
    match inside that branch affects the parent policy.  An ``exp=`` modifier
    in the record is noted when present.

    :param node: Root of the SPF resolution tree.
    :type node: _SPFNode
    :param indent: Current indentation level (internal; starts at 0).
    :type indent: int
    :returns: Lines of text representing the tree.
    :rtype: list[str]
    """
    pad = "  " * indent
    lines: list[str] = []

    if node.macro_skip:
        lines.append(
            f"{pad}{'↳ ' if indent else ''}{node.domain}: "
            "(contains macros – not followed)"
        )
        return lines
    if node.error:
        lines.append(f"{pad}⚠  {node.domain}: {node.error}")
        return lines

    # Build the label for this node.
    arrow = "↳ " if indent else ""
    qualifier_note = ""
    if indent:
        q_map = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
        qualifier_note = (
            f" [qualifier: {node.qualifier}{q_map.get(node.qualifier, '')}]"
        )
    lines.append(f"{pad}{arrow}{node.domain}{qualifier_note}: {node.record}")

    # Surface exp= modifier if present.
    exp_term = next(
        (t for t in node.record.split() if t.lower().startswith("exp=")), None
    )
    if exp_term:
        lines.append(
            f"{pad}  ℹ  exp= modifier found ({exp_term}): "
            "an explanation TXT record will be returned to senders on Fail."
        )

    for child in node.includes:
        lines.extend(_flatten_detail_lines(child, indent + 1))
    if node.redirect:
        lines.extend(_flatten_detail_lines(node.redirect, indent + 1))

    return lines


# ---------------------------------------------------------------------------
# Policy strictness helpers
# ---------------------------------------------------------------------------


def _has_redirect(terms: list[str]) -> bool:
    """Return ``True`` if *terms* contains a ``redirect=`` modifier.

    :param terms: Whitespace-split tokens from an SPF record.
    :rtype: bool
    """
    return any(t.lstrip("+-~?").lower().startswith("redirect=") for t in terms)


def _effective_all(record: str, tree: _SPFNode | None) -> str | None:
    """Return the effective ``all`` qualifier for the record.

    If the top-level record has no ``all`` but has a ``redirect=``, follows
    the redirect to find its ``all`` term (RFC 7208 §6.1: redirect replaces
    the whole record when no explicit ``all`` is present).  Also checks any
    include: children that themselves carry a redirect=, so the walk covers
    one additional level of indirection.

    :param record: Raw top-level SPF record string.
    :type record: str
    :param tree: Resolved SPF tree, or ``None`` if not yet resolved.
    :type tree: _SPFNode or None
    :returns: The ``all`` qualifier string (e.g. ``"-all"``), or ``None``
        if neither the record nor its redirect contains one.
    :rtype: str or None
    """
    terms = record.split()
    all_term = next((t for t in terms if re.match(r"[+\-~?]?all$", t, re.I)), None)
    if all_term:
        return all_term

    # No `all` – check the direct redirect node first.
    if tree and tree.redirect and tree.redirect.record and not tree.redirect.error:
        redirect_terms = tree.redirect.record.split()
        found = next(
            (t for t in redirect_terms if re.match(r"[+\-~?]?all$", t, re.I)), None
        )
        if found:
            return found
        # One further level: the redirect target itself may redirect.
        if tree.redirect.redirect and tree.redirect.redirect.record:
            deep_terms = tree.redirect.redirect.record.split()
            found = next(
                (t for t in deep_terms if re.match(r"[+\-~?]?all$", t, re.I)), None
            )
            if found:
                return found

    return None  # truly missing


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_spf(domain: str) -> SPFResult:
    """Look up and validate the SPF record for *domain* (RFC 7208).

    Recursively resolves ``include:`` and ``redirect=`` targets to report
    the true cross-tree DNS lookup count and the full authorised sender
    tree.  Macro-containing targets (RFC 7208 §7) are noted but not
    followed.

    Checks performed:

    * §3.2  — Exactly one SPF TXT record.
    * §4.6.4 — Total DNS lookup count ≤ 10.
    * §4.6.4 — Void lookup count ≤ 2.
    * §4.7  — Implicit ``?all`` when no ``all`` term and no ``redirect=``.
    * §5.2  — ``include:`` qualifier surfaced; nested ``+all`` flagged.
    * §5.5  — ``ptr`` mechanism deprecation warning.
    * §6.1  — ``redirect=`` replaces record; effective ``all`` followed.
    * §6.2  — ``exp=`` modifier noted in resolution output.
    * §7    — Macro-containing targets noted and skipped.

    :param domain: The domain whose SPF TXT record should be validated.
    :type domain: str
    :returns: Result containing the raw record string and
        :class:`~mailvalidator.models.CheckResult` items for the version tag,
        policy (``all`` qualifier), include resolution tree, DNS lookup
        count, void lookup count, and any ``ptr`` deprecation warnings.
    :rtype: SPFResult
    """
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
    """Validate an SPF record string and append results to *result*.

    :param record: Raw SPF TXT record string (e.g. ``"v=spf1 include:… -all"``).
    :param domain: Domain the record belongs to; used as root for tree walking.
    :param result: :class:`~mailvalidator.models.SPFResult` to append check items to.
    """
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
        # Pass an empty set; _walk_spf uses immutable updates internally so
        # sibling branches do not share visited state.
        tree = _walk_spf(domain, visited=set())

    # --- 'all' policy ---
    explicit_all = next((t for t in terms if re.match(r"[+\-~?]?all$", t, re.I)), None)
    has_redirect_mod = _has_redirect(terms)
    effective = _effective_all(record, tree)

    if explicit_all is None and not has_redirect_mod:
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
        has_errors = any("⚠" in dl for dl in detail_lines)
        result.checks.append(
            CheckResult(
                name="SPF Include Resolution",
                status=Status.WARNING if has_errors else Status.OK,
                details=detail_lines,
            )
        )

    # --- Nested +all inside include: (§5.2 security hazard) ---
    if tree is not None and _has_nested_plus_all(tree):
        result.checks.append(
            CheckResult(
                name="Nested +all in include:",
                status=Status.ERROR,
                details=[
                    "An included record contains '+all' (or bare 'all'), which authorises every "
                    "host on the Internet to match that include:. This is a security hazard even "
                    "if the top-level record uses -all or ~all. Audit the include: chain and "
                    "remove or replace the offending +all."
                ],
            )
        )

    # --- DNS lookup count (recursive, §4.6.4) ---
    if tree is not None:
        total = _count_lookups(tree)
    else:
        total = sum(
            1
            for t in terms
            if any(
                t.lstrip("+-~?").lower() == m
                or t.lstrip("+-~?").lower().startswith(m + ":")
                or t.lstrip("+-~?").lower().startswith(m + "=")
                or t.lstrip("+-~?").lower().startswith(m + "/")
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

    # --- Void lookup count (§4.6.4) ---
    if tree is not None:
        void_total = _count_void_lookups(tree)
        if void_total > _MAX_VOID_LOOKUPS:
            result.checks.append(
                CheckResult(
                    name="Void Lookup Count",
                    status=Status.ERROR,
                    value=f"{void_total}/{_MAX_VOID_LOOKUPS}",
                    details=[
                        f"SPF void lookup count is {void_total}, exceeding the RFC 7208 §4.6.4 "
                        f"limit of {_MAX_VOID_LOOKUPS}. A void lookup is a DNS query that returns "
                        "no records (NXDOMAIN or empty answer). Receivers treat this as a PermError."
                    ],
                )
            )
        elif void_total > 0:
            result.checks.append(
                CheckResult(
                    name="Void Lookup Count",
                    status=Status.WARNING,
                    value=f"{void_total}/{_MAX_VOID_LOOKUPS}",
                    details=[
                        f"{void_total} include: or redirect= target(s) returned no SPF record. "
                        "Approaching the RFC 7208 §4.6.4 void lookup limit of 2."
                    ],
                )
            )


def _emit_all_check(
    all_term: str,
    result: SPFResult,
    via_redirect: bool = False,
) -> None:
    """Append the ``SPF Policy`` :class:`~mailvalidator.models.CheckResult` for *all_term*.

    Grading per RFC 7208 and the NCSC-NL mail test procedure:

    - ``-all`` → :attr:`~mailvalidator.models.Status.OK` (strict fail).
    - ``~all`` → :attr:`~mailvalidator.models.Status.OK` (softfail; preferred
      for sending domains to avoid blocking forwarded mail).
    - ``?all`` → :attr:`~mailvalidator.models.Status.WARNING` (neutral; no protection).
    - ``+all`` → :attr:`~mailvalidator.models.Status.ERROR` (pass; critical
      misconfiguration).

    :param all_term: The raw ``all`` term from the SPF record (e.g. ``"-all"``).
    :param result: :class:`~mailvalidator.models.SPFResult` to append the check to.
    :param via_redirect: When ``True``, the term was found in a
        ``redirect=`` target rather than the top-level record.
    """
    suffix = " (via redirect)" if via_redirect else ""
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
