"""Guided provider: a catalogue of links for services with no API, worked through by hand."""
import json
from importlib.resources import files

from panic.model import Account, Phase, Snapshot, Step, Tier

# (kind, phase, wording); order is the order the owner works through them.
KINDS = (
    ("sign_out", Phase.FREEZE, "sign out everywhere"),
    ("devices", Phase.FREEZE, "review devices and sessions"),
    ("apps", Phase.PURGE, "remove connected apps you do not recognise"),
    ("two_factor", Phase.PURGE, "check two-step verification"),
    ("recovery", Phase.PURGE, "check recovery details"),
    ("password", Phase.PURGE, "change the password"),
)


def load_services() -> dict:
    return json.loads((files("panic") / "guided_services.json").read_text())


class Guided:
    provider = "guided"

    def __init__(self, custom: dict | None = None):
        self.services = {**load_services(), **(custom or {})}

    def catalog(self, account: Account) -> list[Step]:
        entry = self.services[account.id.split(":", 1)[0]]
        note = "" if entry["verified"] else " (link not verified)"
        return [Step(account.id, kind, phase, Tier.GUIDED, f"{entry['name']}: {what}{note}", entry["links"][kind])
                for kind, phase, what in KINDS if kind in entry["links"]]

    def snapshot(self, account: Account) -> Snapshot:
        return {}

    def run(self, step: Step, baseline: Snapshot) -> None:
        raise NotImplementedError(f"{step.action} is a guided step")

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        return None
