"""`panic checkup`: what each account's settings show, and a checklist of what no API can see. Never writes to a provider."""
from dataclasses import dataclass
from typing import Literal

DAYS = 90
GROUPS = (("fix", "Fix now"), ("unknown", "Unknown"), ("good", "Good"))
ANSWERS = {"y": "yes", "yes": "yes", "n": "no", "no": "no", "u": "unsure", "unsure": "unsure"}

# (vault key, question, what it is, link); "no" and "unsure" both mean fix it.
CHECKLIST = [
    ("port_pin", "Have you set a port-out PIN (number transfer lock) with your mobile carrier?",
     "A port-out PIN with your mobile carrier, so nobody can move your number to their SIM",
     "https://www.ic3.gov/PSA/2022/PSA220208"),
    ("passkeys", "Do your main email and your bank sign in with a passkey?",
     "Passkeys on your main email and your bank", "https://passkeys.directory/"),
    ("icloud_adp", "Is iCloud Advanced Data Protection on? (Answer y if you have no iPhone.)",
     "iCloud Advanced Data Protection (or no iPhone)", "https://support.apple.com/en-us/108756"),
    ("offline_photos", "Do you keep an offline copy of your photos (a drive that is not always connected)?",
     "An offline copy of your photos", "https://takeout.google.com/"),
    ("recovery_contact", "Have you set up a recovery contact you trust?",
     "A recovery contact you trust", "https://support.apple.com/en-us/102641"),
]


@dataclass(frozen=True)
class Check:
    account: str
    name: str
    status: Literal["fix", "unknown", "good"]
    detail: str
    link: str | None = None


def posture(conn, account) -> list[Check]:
    """A connector's checks; one it cannot read is "unknown", never "good"."""
    read = getattr(conn, "posture", None)
    if read is None:
        return []
    try:
        return read(account)
    except Exception as e:
        return [Check(account.id, "read", "unknown", f"Could not read this account: {str(e) or type(e).__name__}")]


def ask(saved: dict, now: float, again: bool) -> dict:
    """Answers for the items not answered in the last DAYS days (every item with `again`)."""
    out = {}
    for key, question, *_ in CHECKLIST:
        if again or key not in saved or now - saved[key]["at"] >= DAYS * 86400:
            while (answer := ANSWERS.get(input(f"{question} [y/n/u] ").strip().lower())) is None:
                print("Answer y (yes), n (no) or u (unsure).")
            out[key] = {"answer": answer, "at": now}
    return out


def checklist(answers: dict) -> list[Check]:
    return [Check("You", key, "good" if answers[key]["answer"] == "yes" else "fix", what, link)
            for key, _, what, link in CHECKLIST if key in answers]


def render(checks: list[Check]) -> str:
    lines = []
    for status, title in GROUPS:
        group = [f"  {c.account}: {c.detail}" + (f" — {c.link}" if c.link else "") for c in checks if c.status == status]
        lines += [title, *(group or ["  Nothing."])]
    return "\n".join(lines)
