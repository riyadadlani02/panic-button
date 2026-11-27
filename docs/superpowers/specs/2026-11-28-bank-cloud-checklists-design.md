# Bank and cloud checklists: design

Approved by Riya, 28 Nov 2026 ("Approve"), as project 1 of 5 (then one-click connect, AWS, Dropbox Business, Google Cloud, Azure; Windows blocked).

## Why

Banks and consumer cloud services give no tool a way to lock an account or sign out an intruder. The useful thing panic button can do is put the right official pages in the right order the moment something happens.

## What

- Add guided services: India (SBI, HDFC Bank, ICICI Bank, Axis Bank, Kotak Mahindra Bank, Paytm, PhonePe, Google Pay India), UK (Barclays, HSBC UK, Lloyds Bank, NatWest, Santander UK, Monzo, Starling Bank), US (Chase, Bank of America, Wells Fargo, Citi, Capital One, Venmo, Cash App), global (PayPal, Wise, Revolut), cloud (iCloud, Google Photos and Drive, Dropbox, OneDrive).
- Two new step kinds, first in every press, in this order: `freeze_card` ("freeze your cards") and `fraud_help` ("report it to the fraud team, or call the number on the back of your card"). Both are FREEZE phase.
- Each catalogue entry gains `country` (`IN`, `UK`, `US` or `global`) and `category` (`bank`, `payments`, `cloud`, `other`).
- No phone numbers anywhere in the catalogue.
- Every link comes from the provider's own site. A script, `scripts/check-guided-links.py`, fetches each link and marks an entry `verified` only when every link answers on the provider's own registrable domain; anything blocked or redirected elsewhere stays unverified, and the app keeps saying "(link not verified)".
- `panic setup` (and the app's setup wizard, which runs it) lists "Another service" grouped by country and category.

## Constraints

- Links: `https` only and accepted by the existing `valid_link`.
- Existing entries keep working; old vaults with custom guided entries are unaffected.
- Nothing is detected or locked automatically for these services.
- Commits authored by Riya Dadlani only.
