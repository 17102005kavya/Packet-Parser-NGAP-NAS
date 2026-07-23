"""
NAS Cause Classification Utilities.

Provides cause-value helpers shared across all procedure analyzers so that
NAS 5GMM/5GSM cause values are classified consistently and in one place.

References:
  - 3GPP TS 24.501 Table 9.11.3.2.1  (5GMM cause values)
  - 3GPP TS 24.501 Table 9.11.4.2.1  (5GSM cause values)
"""

from typing import Optional


# ---------------------------------------------------------------------------
# 5GMM cause values that represent a normal/expected protocol event and should
# NOT be treated as a genuine failure by procedure analyzers.
#
# Cause #21 (0x15) — "Synch failure": the UE is reporting that the received
# SQN is out of range and initiating AUTS-based resynchronisation.  The AMF
# is expected to re-derive keys and re-issue an Authentication Request.  This
# is a well-defined, recovery path in 5G-AKA (TS 33.501 §6.1.3.4) and is
# NOT an authentication failure from the network's perspective.
# ---------------------------------------------------------------------------
_5GMM_BENIGN_CAUSES: dict[str, str] = {
    "21":            "synch failure",
    "0x15":          "synch failure",
    "synch failure": "synch failure",
    "synch_failure": "synch failure",
}

# (Dead code removed: _5GMM_BENIGN_SUBSTRINGS frozenset was used by the old
# substring-matching implementation of is_benign_nas_cause.  The function now
# does an exact dict lookup against _5GMM_BENIGN_CAUSES above, so the frozenset
# is no longer needed and has been deleted to avoid future confusion.)


def is_benign_nas_cause(cause_str: Optional[str]) -> bool:
    """
    Returns True if *cause_str* represents a known-benign NAS 5GMM cause that
    should NOT be treated as a procedure failure.

    *cause_str* is expected in the format produced by
    ``PacketParser._extract_cause()``, e.g.::

        "5GMM/5GSM cause: 21"
        "5GMM/5GSM cause: synch failure"

    Returns False for any other value, including None.
    """
    if not cause_str:
        return False
    # Expect format "5GMM/5GSM cause: <value>" — take everything after
    # the LAST colon and compare the exact value, not a substring.
    value = cause_str.rsplit(":", 1)[-1].strip().lower()
    return value in _5GMM_BENIGN_CAUSES

def is_synch_failure(cause_str: Optional[str]) -> bool:
    """
    Narrower helper: returns True only if the cause specifically indicates
    SQN resynchronisation (5GMM cause #21 "synch failure").

    Equivalent to ``is_benign_nas_cause`` for now — delegates to the same
    exact dict lookup against ``_5GMM_BENIGN_CAUSES``.  Kept as a separate
    entry-point so call-sites that care specifically about synch-failure
    remain readable and can be updated independently when additional benign
    causes are added to ``_5GMM_BENIGN_CAUSES`` in the future.
    """
    return is_benign_nas_cause(cause_str)


# ---------------------------------------------------------------------------
# 5GSM cause values
# All PDU Session rejection causes in TS 24.501 Table 9.11.4.2.1 represent
# genuine failures — there are no currently-known benign 5GSM causes that
# need special-casing.  This stub is here so future additions have a home.
# ---------------------------------------------------------------------------
def is_benign_5gsm_cause(cause_str: Optional[str]) -> bool:
    """Placeholder: currently no known-benign 5GSM causes."""
    return False
