"""A change not made, and why: nothing was sent to Linode."""
from __future__ import annotations


class Refusal(ValueError):
    """A change not made, and why: nothing was sent to Linode. `accept`: the argument that, set, makes the change anyway
    (accept_risk, for a firewall rule that opens SSH or every port to the whole internet, or that may lock SSH out of an
    attached Linode); the platform's page asks it as a second, explicit confirmation (liminal-platform 0.6.0: a refusal
    naming a field of type accept)."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept
