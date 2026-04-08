"""DKIM base-node DNS conformance check.

What this checks
----------------
RFC 6376 requires that ``<selector>._domainkey.<domain>`` resolves to a valid
DKIM TXT record.  Selectors are chosen by the sending service and are not
discoverable from DNS alone, so mailvalidator cannot enumerate them.

Instead, this check validates the *base node* ``_domainkey.<domain>``:

- An RFC 2308-conformant name server **must** answer ``NOERROR`` (with an
  empty answer section) for an empty non-terminal node, because child labels
  (the selector records) are present beneath it.
- A non-conformant name server answers ``NXDOMAIN``, which causes some
  receivers to abort DKIM verification before even trying the selector lookup.

:func:`~mailvalidator.dns_utils.resolve` is called with ``raise_nxdomain=True``
so ``None`` reliably signals NXDOMAIN, while ``[]`` signals NOERROR/empty
(the correct response for an empty non-terminal).

This is a necessary-but-not-sufficient conformance check.  To verify a
specific selector's record use ``dig <selector>._domainkey.<domain> TXT``.
"""

from __future__ import annotations

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, DKIMResult, Status


def check_dkim(domain: str) -> DKIMResult:
    """Check that ``_domainkey.<domain>`` responds correctly per RFC 2308.

    :param domain: The domain whose DKIM base node should be validated.
    :returns: A :class:`~mailvalidator.models.DKIMResult` containing one
        :class:`~mailvalidator.models.CheckResult` for the base-node conformance
        check.
    :rtype: ~mailvalidator.models.DKIMResult
    """
    result = DKIMResult(domain=domain)
    base_node = f"_domainkey.{domain}"

    # raise_nxdomain=True: returns None on NXDOMAIN, [] on NOERROR/empty.
    records = resolve(base_node, "TXT", raise_nxdomain=True)

    if records is None:
        result.checks.append(
            CheckResult(
                name="DKIM Base Node",
                status=Status.ERROR,
                details=[
                    f"{base_node} returned NXDOMAIN. "
                    "The name server is not RFC 2308-conformant: it must answer "
                    "NOERROR for an empty non-terminal so receivers can detect "
                    "DKIM support without knowing the selector in advance.",
                ],
            )
        )
    else:
        result.checks.append(
            CheckResult(
                name="DKIM Base Node",
                status=Status.OK,
                value=base_node,
                details=[
                    f"{base_node} answered NOERROR (RFC 2308-conformant).",
                    "Note: this confirms DNS infrastructure is DKIM-ready. "
                    "It does not verify that any selector record exists — "
                    "use 'dig <selector>._domainkey.<domain> TXT' to check a specific selector.",
                ],
            )
        )

    return result
