"""Shared detection rules: turn drift from a baseline into findings."""
import json
from typing import Callable

from panic.model import Finding, Severity, Snapshot

TEXT = {
    "rule_forwards_outside": "A mail rule forwards your mail to an outside address.",
    "rule_hides_mail": "A mail rule hides or deletes incoming mail.",
    "forwarding_added": "Mail forwarding was switched on or a forwarding address was added.",
    "delegate_added": "Someone was given delegate access to this mailbox.",
    "pop_enabled": "POP or IMAP access to this mailbox was switched on.",
    "recovery_changed": "A recovery phone or email on this account changed.",
    "key_added": "A new key or token was created.",
    "email_added": "A new email address was added to this account.",
    "repo_access_added": "A new app or key has access to your repositories.",
    "org_access_added": "A new app or key has access to your organisation.",
    "app_consent_added": "A new app was given access to this account.",
    "app_password_added": "A new app password was created on this account.",
    "repo_made_public": "A repository was created as public or made public.",
    "runner_added": "A new self-hosted runner was attached to your repositories.",
    "auth_method_added": "A new sign-in method was added to this account.",
    "provider_flagged_login": "The provider flagged a suspicious sign-in.",
    "changed": "Something else on this account changed since the baseline.",
    "unreadable": "This account could not be read, so it was not checked.",
    "events_unreadable": "This account's activity log could not be read, so it was not checked.",
    "new_access": "New access appeared on this account.",
}


def drift(account_id: str, baseline: Snapshot, snapshot: Snapshot,
          classify: Callable[[str, str], str | None]) -> list[Finding]:
    by_code: dict[str | None, list[str]] = {}
    for cat, items in snapshot.items():
        if cat not in baseline:
            raise KeyError(f"no baseline recorded for {cat} on {account_id}")
        for item in items:
            if item not in baseline[cat]:
                by_code.setdefault(classify(cat, item), []).append(f"{cat}: {item}")
    out = [Finding(account_id, code, Severity.TRIGGER, TEXT[code], tuple(sorted(items)))
           for code, items in by_code.items() if code]
    if None in by_code:
        out.append(Finding(account_id, "changed", Severity.NOTICE, TEXT["changed"], tuple(sorted(by_code[None]))))
    return out


def adopted(baseline: Snapshot, snapshot: Snapshot) -> Snapshot:
    """The snapshot's categories the baseline lacks, taken as baseline: a connector that starts watching a new
    category must not leave an older vault unreadable. A category the baseline has is never taken."""
    return {cat: items for cat, items in snapshot.items() if cat not in baseline}


def gmail_rule_code(item: str, own_domain: str | None) -> str | None:
    try:
        action = json.loads(item).get("action") or {}
        forward = action.get("forward")
        if forward and (own_domain is None or forward.rpartition("@")[2].lower() != own_domain.lower()):
            return "rule_forwards_outside"
        add, remove = action.get("addLabelIds") or [], action.get("removeLabelIds") or []
        if "TRASH" in add or "INBOX" in remove:  # skip-inbox too: unanswered harmless changes are accepted
            return "rule_hides_mail"
    except (ValueError, AttributeError, TypeError):
        return "rule_hides_mail"  # fail closed: a rule we cannot read may hide mail
    return None
