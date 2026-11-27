# Bank and Cloud Checklists Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** About 30 new guided services (banks in India, UK, US, global payments, consumer cloud) with card-freeze and fraud steps, official links checked by a script.

**Spec:** `docs/superpowers/specs/2026-11-28-bank-cloud-checklists-design.md`

## Global Constraints

- New kinds `freeze_card` and `fraud_help`, FREEZE phase, first in `KINDS`, wording exactly "freeze your cards" and "report it to the fraud team, or call the number on the back of your card".
- No phone numbers in the catalogue. Every link `https`, from the provider's own site, accepted by `valid_link`.
- `verified: true` only when the check script confirms every link.
- Commits authored by Riya Dadlani only.

---

### Task 1: Code

**Files:** `panic/guided.py`, `panic/cli_setup.py` (grouped listing), `panic/cli_arm.py` (`--link` accepts the new kinds), create `scripts/check-guided-links.py`; tests in `tests/test_guided.py`, `tests/test_cli_guided.py`, `tests/test_cli_setup.py`.
- [ ] Tests first: a catalogue entry with `freeze_card`/`fraud_help` produces those steps first, in order; `--link freeze_card=https://…` accepted; setup's "Another service" text groups by country and category; the check script's pure function marks an entry verified only when every link's final URL is on the entry's own registrable domain (fake fetcher), and never on a 4xx/5xx or a network error.
- [ ] Implement; full suite; commit `feat: card-freeze and fraud steps, grouped catalogue, link checker`.

### Task 2: Catalogue data

**Files:** `panic/guided_services.json`.
- [ ] For each service in the spec, find the official pages with web search and the provider's site (never guess a URL): freeze card, fraud help, sign out/devices, two-factor, recovery, password, connected apps where they exist. Add `country` and `category` to every entry, including the existing nine.
- [ ] Run `scripts/check-guided-links.py` and set `verified` from its result; list each entry's result in the report.
- [ ] Full suite; commit `feat: banks in India, UK and US, global payments and cloud storage as checklists`.

### Task 3: Words

**Files:** `README.md`, `site/index.html`.
- [ ] README guided section: the new kinds, the services by country, how verification works, no phone numbers. Page: one line in "Where it works" that banks and cloud storage are checklists, with the countries.
- [ ] Commit `docs: bank and cloud checklists`.
