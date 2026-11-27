# Real attacks Nov 2025 – Nov 2026 vs. an account-settings watcher ("panic button")

Research date: 28 Nov 2026. Tool under test: runs on the user's own computer, reads security settings through official APIs, never reads mail content, locks the account and removes attacker additions (mail rules, forwarding, keys, app consents, delegates, sessions).

Caveats up front
- Most big 2026 incidents are enterprise SaaS thefts (Salesforce, npm/GitHub). Consumer photo/iCloud cases are thinly documented in primary sources. Two items (Salesloft Drift, Aug 2025) predate the window; they are included because Gainsight (Nov 2025) and the 2026 Klue case are the same pattern.
- I did not open every primary report; where only a secondary summary was read it is marked (secondary).
- API availability below is from my own knowledge of the providers' documented APIs, not from the incident reports. Verify before building. Rule of thumb: Microsoft 365 and Google Workspace (admin-scoped) expose a lot; consumer Gmail, Outlook.com, iCloud and personal GitHub expose very little.

API availability cheat-sheet (my knowledge, verify)
| Provider | What a watcher can see/act on |
|---|---|
| Google Workspace (admin) | Admin SDK Reports API: login, token (OAuth grant/revoke), user_accounts (recovery/2SV changes), admin, drive, takeout-style events. Directory API: tokens.list/delete, users.signOut, ASPs. Gmail API settings: filters, forwardingAddresses, autoForwarding, delegates. Needs admin consent/domain-wide delegation. |
| Consumer Gmail | Gmail API settings (filters, forwarding, delegates) works with the user's own OAuth. No API to list third-party app grants, devices, sessions or login history; no sign-out-everywhere API. |
| Microsoft 365 / Entra | Graph: auditLogs/signIns (needs Entra P1), auditLogs/directoryAudits, identityProtection/riskDetections (P2), oauth2PermissionGrants, users/{id}/authentication/methods, users/{id}/revokeSignInSessions, mailFolders/inbox/messageRules, mailboxSettings, devices. |
| Outlook.com (personal MSA) | Graph messageRules/mailboxSettings work; no sign-in logs, no app-grant list, no session revoke API (account.microsoft.com only). |
| GitHub | REST: list/delete SSH keys, GPG keys, deploy keys, repo webhooks, Actions secrets metadata, installations. Personal-account security log: no public API (web UI only). Org audit log API: Enterprise Cloud only. PAT listing for a user: no API. |
| Slack | Audit Logs API: Enterprise Grid only. Otherwise auth.test/admin.* limited. |
| Okta / Salesforce | Okta System Log API (admin). Salesforce: OauthToken/ConnectedApplication queryable by admin; login/API event logs need Shield Event Monitoring (paid). |
| Apple iCloud | No API at all. |
| Carriers / exchanges / wallets | No account-settings API for the user. |

---

## 1. Salesloft Drift OAuth token theft (Aug 2025; context for #2, #3)
- Hit: 700+ orgs' Salesforce instances; a few Google Workspace accounts via Drift Email. Stolen: Accounts/Cases/Users records, then secrets inside them (AWS keys, Snowflake tokens, passwords).
- Technique: attacker stole Drift's OAuth/refresh tokens at the vendor, called Salesforce APIs as the Drift connected app from Tor/cloud IPs, bulk SOQL, deleted query jobs. Victim accounts changed in no way: the grant already existed.
- Earliest signal: only anomalous API volume/IP for the existing connected app (Salesforce Event Monitoring, paid). For Google: Drift Email token usage from new IPs in the Reports API `token` activity.
- Verdict: **out of reach** (for a user-side tool). Theft happened at the vendor using a legitimate pre-existing grant. A watcher could only have limited it afterwards by revoking the grant once the vendor announced the breach, or by flagging "unused-for-90-days, over-scoped app".
- Sources: https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift ; https://www.bleepingcomputer.com/news/security/salesloft-breached-to-steal-oauth-tokens-for-salesforce-data-theft-attacks

## 2. Gainsight / Salesforce connected-app token abuse (Nov 2025)
- Hit: 200+ Salesforce instances (Google count; ShinyHunters claimed 285). Stolen: business contact and licensing data, CRM records.
- Technique: tokens for Gainsight-published connected apps (possibly originating from the Drift breach, unconfirmed) used against customer orgs; Salesforce revoked on 19 Nov 2025.
- Earliest signal: unusual API activity from the Gainsight connected app (Shield Event Monitoring). Nothing in a user's own settings.
- Verdict: **out of reach** before disclosure; **would have limited it** only if a watcher inventories connected apps and the user acts on vendor breach notice (revoke + rotate). Weak.
- Sources: https://www.theregister.com/2025/11/21/shinyhunters_salesforce_gainsight_breach/ ; https://www.bleepingcomputer.com/news/security/salesforce-investigates-customer-data-theft-via-gainsight-breach/amp/

## 3. Vishing for a malicious Salesforce connected app + Klue vendor compromise (mid-2025 to Jun 2026; Microsoft report 13 Jul 2026)
- Hit: retail, education, manufacturing orgs (unnamed); Klue (Jun 2026, Storm-3138) integration credentials used against customers. Stolen: CRM accounts, contacts, support cases, via bulk queries/report exports.
- Technique (path 1): attacker phones employee as "IT support", walks them through authorising a lookalike "Data Loader" connected app; app inherits user's rights; API export. (path 2): vendor-held credentials stolen, used from new IPs.
- Account changes: new connected-app authorisation (path 1); none (path 2). Microsoft says integration traffic is hard to tell from legit traffic.
- Earliest signal: the new connected-app grant (Salesforce OauthToken/setup audit trail; admin-visible). For Google Workspace/M365 variants: Reports `token` authorize event; Graph oauth2PermissionGrants.
- Verdict: path 1 **would have limited it** (alert on new grant within minutes, user/admin revokes before bulk export finishes; honest caveat: exports of large orgs can finish in minutes). Path 2 **out of reach**.
- Source: https://microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse

## 4. ShinyHunters-branded SSO vishing (Okta, Entra, Google) (Jan 2026; ~100 orgs)
- Hit: ~100 orgs incl. Canva, Betterment, Crunchbase, SoundCloud (secondary: The Register/SOCRadar). Stolen: SaaS data via bulk export, Google Takeout, Data Loader, SharePoint downloads; then extortion.
- Technique: caller poses as IT, victim enters creds + MFA on a victim-branded phishing page; attacker enrolls own device as MFA factor (one case: Okta FastPass "Passkey" emulated device); authorises OAuth apps (e.g. "ToogleBox Recall"); deletes "security method enrolled" notification emails; mass export.
- Account changes: new MFA factor, new OAuth app, deleted notification mail, Takeout export.
- Earliest signal: MFA factor enrol/reset (Okta System Log `user.mfa.factor.enroll`, Entra directoryAudits auth-method change, Google Reports `user_accounts`); OAuth grant (Reports `token`). Mandiant calls MFA lifecycle change the highest-fidelity signal.
- Verdict: **would have limited it** where the org uses a self-hosted watcher with admin API rights: alert on new MFA factor from a new IP, kill sessions and remove the factor. Gap: attacker already holds a valid session and may export in the first minutes; and a single-user tool cannot see an org's Okta log unless the admin runs it.
- Sources: https://cloud.google.com/blog/topics/threat-intelligence/defense-against-shinyhunters-cybercrime-saas ; https://www.theregister.com/2026/01/26/shinyhunters_okta_sso_campaign/ ; https://www.helpnetsecurity.com/2026/02/02/shinyhunters-mfa-social-engineering/

## 5. Shai-Hulud 2.0 npm worm (21-26 Nov 2025)
- Hit: developers/CI using Zapier, ENS, PostHog, Postman packages; 25,000+ GitHub repos used as dumps; Wiz verified 775 GitHub tokens, 373 AWS, 300 GCP, 115 Azure creds in a sample. Stolen: GitHub PATs, cloud keys, Actions secrets, secret-manager contents; some private repos downloaded/published.
- Technique: trojanised package ran at preinstall on dev machine/CI, harvested env/config/cloud-metadata secrets, pushed them to new public GitHub repos, created malicious workflows and self-hosted runner named SHA1HULUD.
- Account changes: new public repos, new workflow files, new self-hosted runner, private repos made public, later use of stolen AWS keys / PATs.
- Earliest signal: new repo/workflow/runner created from the user's token (GitHub REST can list repos, runners, workflows; personal security log has no API). Credential abuse is visible in AWS CloudTrail, not in a settings watcher.
- Verdict: **would have limited it** for the GitHub-side damage (detect new public repos/runners, revoke PAT, rotate keys; secrets already copied before that, so rotation is mandatory). **Out of reach** for preventing the initial secret theft: malware ran on the device.
- Sources: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack ; https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ ; https://www.theregister.com/2025/11/24/shai_hulud_npm_worm/

## 6. Mini Shai-Hulud / TanStack (11 May 2026)
- Hit: 42 @tanstack packages (84 versions) in 6 minutes; wider wave of 170 packages incl. Mistral AI, Guardrails AI (PyPI). Stolen: CI OIDC tokens and GitHub tokens; payload installed `gh-token-monitor` that re-exfiltrates tokens and reportedly wipes the disk if the token is revoked (dead-man's switch, per Carlini/Orca).
- Technique: cache poisoning in release workflow, code exec in CI minted an OIDC publish token (no classic npm token stolen, per TanStack/Wiz/Appwrite).
- Earliest signal: unexpected workflow runs/new package versions (GitHub Actions and npm audit logs). Nothing in a personal-account settings feed.
- Verdict: **out of reach** for the compromise (CI/vendor side); **would have limited** only post-disclosure token revocation. Note the revoke-triggers-wipe risk: an auto-revoke feature could be harmful here; Orca advises removing the daemon first.
- Sources: https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html ; https://www.securityweek.com/tanstack-mistral-ai-uipath-hit-in-fresh-supply-chain-attack/ ; https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/

## 7. Device-code phishing, EvilTokens PhaaS and successors (Feb-Jul 2026; 340+ M365 orgs by mid-March)
- Hit: M365 orgs worldwide, finance/exec/admin users (Microsoft, 6 Apr 2026). Stolen: access+refresh tokens, mail with wire details/invoices, directory data.
- Technique: fake invoice/RFP/voicemail lure -> page requests a fresh device code, copies it to clipboard, sends victim to microsoft.com/devicelogin -> victim signs in with MFA -> attacker polls and gets tokens; may register a device within ~10 min to get a Primary Refresh Token; creates inbox rules with special-character names; Graph recon.
- Account changes: device-code sign-in (error 50199 then success), new device registration, new inbox rule, Graph mail access from odd ISP.
- Earliest signal: Graph signIns (authentication protocol deviceCode; needs Entra P1), directoryAudits device registration, `messageRules` list. A rule scan works on any M365 mailbox, including with no P1.
- Verdict: **would have limited it**: removing the rule, revoking sessions (`revokeSignInSessions`), deleting the device. Not "stopped": tokens are issued before any setting changes, and a fast attacker reads mail in minutes. Blocking device-code flow by Conditional Access would stop it outright (preventive config, which a settings tool can recommend/check).
- Sources: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign/ ; https://labs.cloudsecurityalliance.org/research/csa-research-note-oauth-device-code-phishing-m365-20260325-c/ (secondary)

## 8. AiTM + SharePoint lure BEC chain against energy-sector firms (reported 21 Jan 2026)
- Hit: multiple energy orgs (unnamed). Stolen: credentials/session, mailbox access; 600+ onward phishing emails to contacts.
- Technique: phishing from a trusted compromised partner -> SharePoint-looking link -> AiTM proxy captures password+session cookie -> attacker signs in from another IP, creates a rule that deletes all incoming mail and marks read, sends 600+ emails, deletes bounces/OOO replies, replies to confirm legitimacy; adds MFA method in some cases.
- Account changes: new inbox rule, new MFA method, mass sent mail, new sign-in from different IP.
- Earliest signal: inbox rule created (Graph messageRules / Exchange audit), MFA method added (Graph authentication methods, directoryAudits), sign-in from new IP using stolen session cookie (Entra ID Protection "anomalous token"/"stolen session cookie" detections need P2; plain signIns need P1).
- Verdict: **would have limited it**: a rule that deletes all inbound mail is a near-zero-false-positive alert; revoking sessions and removing rule/MFA method cuts the 600-email spread and secondary victims. It would not prevent the first session's access.
- Source: https://www.microsoft.com/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint/

## 9. Tycoon 2FA AiTM phishing-as-a-service (peak 2025; disrupted 4 Mar 2026, persisted after)
- Hit: ~96,000 distinct victims since 2023 incl. 55,000+ Microsoft customers; 100+ Health-ISAC members, NY hospitals/schools. Stolen: M365/Gmail credentials and session cookies, then BEC/fraud/ransomware access. (Microsoft says ~62% of phishing it blocked by mid-2025.)
- Technique: reverse-proxy login page relays password and MFA code to real provider, steals the post-MFA session cookie; operators replay it from VPS infrastructure.
- Earliest signal: sign-in from new IP/ASN with the same session (Entra signIns / Google Reports `login`); follow-on persistence: rules, forwarding, new MFA, app consent. I found no source documenting Tycoon-specific inbox rules; that is generic AiTM tradecraft (see #8).
- Verdict: **would have limited it** only through the post-compromise persistence checks; the cookie theft itself is **out of reach**. CrowdStrike/Barracuda report the kit's tooling survived the takedown. Only phishing-resistant MFA (passkeys/FIDO2) stops AiTM, and a watcher cannot add that for the user (it can check whether it is enrolled).
- Sources: https://blogs.microsoft.com/on-the-issues/2026/03/04/how-a-global-coalition-disrupted-tycoon/ ; https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown ; https://thehackernews.com/2026/03/europol-led-operation-takes-down-tycoon.html

## 10. "Operation CloudFire": Google Calendar-invite AiTM against Workspace (mid-Aug to Nov 2026)
- Hit: corporate Google Workspace users; 68,676 messages blocked in one month in one vendor's customer base; 8,570 compromised sender addresses. Stolen: live Google sessions -> mail, Drive, ability to grant OAuth. (Article is sponsored by Material Security; treat counts as vendor claims.)
- Technique: calendar invites with Google-redirector links -> Turnstile gate -> live reverse proxy of Google sign-in relays password, MFA (SMS/TOTP/number-match) and recovery prompts -> live session; compromised accounts mail their own contacts.
- Earliest signal: Workspace Reports `login` events (new IP/device), then `token` (new OAuth grant), Gmail filter/forwarding changes, `user_accounts` recovery/2SV changes. Admin-only.
- Verdict: **would have limited it** for Workspace orgs where the admin runs the tool (sign-out + token revoke + filter removal). **Out of reach** for consumer Gmail (no login/token APIs). Does not stop the first minutes of access.
- Source: https://bleepingcomputer.com/news/security/google-calendar-phishing-campaign-hijacks-sessions-bypasses-mfa (sponsored)

## 11. OAuth consent phishing of prominent people and contacts (since late 2025; FBI PSA 1 Sep 2026)
- Hit: prominent individuals, families, acquaintances (Microsoft/Google accounts). Stolen: ability to read/send mail and access files (PSA gives no confirmed data list). Related July 2026 case: Ukrainian civic group OPORA (secondary).
- Technique: attacker registers app with broad scopes -> lure ("shared file", "draft article", "event invite") by email or messaging app -> victim signs in on the genuine login page and clicks Allow -> persistent token; password reset does not remove it, MFA irrelevant.
- Account changes: one new third-party app grant. Nothing else.
- Earliest signal: the grant. Workspace: Reports `token` authorize + Directory tokens.list. M365: oauth2PermissionGrants / Entra consent audit. Consumer Google and consumer Microsoft: **no API to list or revoke grants** (only the web page), so a desktop tool can prompt the user but cannot automate it.
- Verdict: **would have stopped it** for Workspace/M365 tenants only if the tool revokes the grant before material is read (race measured in seconds to minutes; mail read is immediate, so "limited" is more honest). For consumer accounts: **out of reach** for automation; at best a reminder to review `myaccount.google.com/connections`.
- Source: https://www.ic3.gov/PSA/2026/PSA260901

## 12. Infostealers and replayable sessions: Storm, Lumma, VoidStealer (2026; Lumma cookie-restore technique first reported Nov 2023)
- Hit: individuals and employees worldwide. NordVPN counts 52.4 billion stolen cookies in Jun 2025-Jun 2026 (vendor stat). Storm panel showed 1,715 log entries (author could not confirm all real). Stolen: browser passwords, cookies, wallets, tokens, Telegram/Signal/Discord sessions.
- Technique: malware (phishing/cracked software/ClickFix) on the device; bypasses Chrome App-Bound Encryption (VoidStealer, Glove, others); Storm ships raw data to the operator and decrypts server-side, then restores a Google session from a refresh token with a geo-matched proxy. Reported Lumma/Rhadamanthys cookie restore keeps session valid after password change.
- Account changes: none at first; later a new session/device from a residential proxy; then whatever the attacker adds (forwarding, app grants, new recovery info).
- Earliest signal: Workspace `login` events from new IP/device; consumer accounts: none via API.
- Verdict: infection and theft **out of reach**. Afterward **would have limited it** only when the tool can force global sign-out/token revocation (Workspace: signOut, M365: revokeSignInSessions) and clean persistence. For consumer Google: the user must change password AND use "sign out of all devices"; no API. Important: a watcher on the same infected PC is also compromised (it can be read or disabled by the stealer).
- Sources: https://www.bleepingcomputer.com/news/security/the-silent-storm-new-infostealer-hijacks-sessions-decrypts-server-side/amp/ ; https://www.bleepingcomputer.com/news/security/lumma-malware-can-allegedly-restore-expired-google-auth-cookies/ ; https://www.kaspersky.com/blog/chrome-application-bound-encryption-bypass-voidstealer/55735/ ; https://nordvpn.com/blog/stolen-cookies-research/

## 13. iCloud takeover, family photos and videos lost (reported Mar 2026; Charlotte NC)
- Hit: one individual (local news; anecdote, entry method unknown). Lost: tens of thousands of photos/videos stored only in iCloud; Apple Pay used for recurring charges.
- Technique: login attempt alert from Jakarta, user denied it, then locked out; emails said password and trusted phone number were changed. Apple only suggested Stolen Device Protection. Wider 2026 trend: fake Apple login pages harvest Apple IDs (Malwarebytes, Apr 2026).
- Account changes: password, trusted phone number (recovery factor).
- Earliest signal: the trusted-phone / password change emails. **Apple offers no API**; a watcher cannot read iCloud settings or lock the account, and (by design here) does not read mail so it cannot even see Apple's notification emails.
- Verdict: **out of reach**. Closest help: checklist guidance (enable Advanced Data Protection/Stolen Device Protection, keep an offline copy of photos, set a recovery contact).
- Sources: https://www.alaskasnewssource.com/2026/03/09/icloud-hack-costs-mom-thousands-cherished-photos-videos/ ; https://www.malwarebytes.com/blog/news/2026/04/icloud-storage-is-full-scam-is-back-and-now-it-wants-your-payment-details

## 14. SIM-swap gang taking over crypto exchange accounts (Poland arrests, 25 Jun 2026)
- Hit: individual crypto holders; est. millions of USD stolen, at least ~$5M laundered. Stolen: exchange-account balances.
- Technique: breached telecom partner systems and employee mailboxes, swapped SIMs, intercepted SMS/email codes, reset exchange passwords. FBI/HSI assisted. (IC3 2025: SIM swap was 10% of cyber threat types; no dollar figure found.)
- Account changes: at the carrier (SIM) and at the exchange (password/2FA reset, withdrawal address changes).
- Earliest signal: SIM change at carrier (no user API; carrier alerts only). Email forwarding/filter or new-session signals on the victim's email if the gang also pivoted there.
- Verdict: **out of reach** for the SIM swap itself. **Would have limited it** only if attackers pivoted into Gmail/M365 and added a forwarding rule or app grant. A checklist item "move 2FA off SMS, set carrier port-out PIN" is the real defence.
- Sources: https://bleepingcomputer.com/news/security/poland-busts-sim-swapping-gang-tied-to-millions-in-crypto-theft ; https://www.securityweek.com/fbi-cybercrime-losses-neared-21-billion-in-2025/

## 15. $282M hardware-wallet social-engineering theft (10 Jan 2026)
- Hit: single holder; ~2.05M LTC + 1,459 BTC. Funds swapped to Monero, bridged via THORChain.
- Technique: reported (Cointelegraph/Halborn) impersonation of Trezor support to extract the seed/authorise transfers; ZachXBT's own account of the method unconfirmed. 
- Account changes: none in any online account; seed given away.
- Verdict: **out of reach**. No account setting exists to watch.
- Sources: https://cointelegraph.com/news/crypto-user-loses-282m-bitcoin-litecoin-social-engineering-attack ; https://thedefiant.io/news/defi/zachxbt-highlights-usd282m-theft-of-bitcoin-and-litecoin-in-hardware-wallet-scam ; https://crypto.news/282m-in-bitcoin-litecoin-stolen-hardware-wallet-scam/

## 16. Wallet-drainer approval phishing (fake MetaMask emails Jan 2026; 999,999 USDT on 8 Jul 2026)
- Hit: hundreds of EVM wallets in Jan 2026 (>$107k, ZachXBT); one victim ~$1M USDT in July. Chainalysis (reported): ~158,000 personal wallet compromises in 2025.
- Technique: spoofed email/QR/ad -> victim signs a token approval -> script drains exact balance.
- Account changes: on-chain approval only.
- Verdict: **out of reach** for an account-settings tool. Adjacent: could surface "revoke token approvals" as a checklist link; wallet-level tools do that, not this one.
- Sources: https://cryptoslate.com/hundreds-of-evm-wallets-drained-what-to-check-before-you-update/ ; https://cointelegraph.com/news/trader-loses-1m-after-signing-phishing-token-approval

## 17. Mixpanel smishing breach, OpenAI API customer metadata (8-9 Nov 2025; edge of window)
- Hit: Mixpanel (vendor); OpenAI API users' names, emails, approximate location, OS/browser exposed. No chats, keys or payment data.
- Technique: SMS phishing of a vendor employee; dataset exported.
- Verdict: **out of reach** (vendor side; data about victims, not their accounts). Relevance: it fuels targeted phishing later.
- Sources: https://www.securityweek.com/openai-user-data-exposed-in-mixpanel-hack/ ; https://www.bitdefender.com/en-us/blog/hotforsecurity/openai-breach-alert-mixpanel-incident-exposes-limited-api-user-data

Not found / gaps: no primary source for a 2026 consumer Google Photos mass takeover; no 2026 MFA-fatigue incident with primary detail (help-desk vishing from the 2025 Scattered Spider/M&S era is covered indirectly by #3 and #4); no verifiable 2026 US SIM-swap indictment; SIM-swap loss totals in IC3 2025 not found.

---

## Scorecard
| # | Incident | Verdict |
|---|---|---|
| 1 | Salesloft Drift | out of reach |
| 2 | Gainsight | out of reach / weak limit |
| 3 | Vishing connected app + Klue | limited (path 1); out (path 2) |
| 4 | SSO vishing + MFA enrol | limited |
| 5 | Shai-Hulud 2.0 | limited (GitHub side); theft out |
| 6 | Mini Shai-Hulud | out of reach |
| 7 | Device-code phishing | limited |
| 8 | AiTM SharePoint BEC | limited |
| 9 | Tycoon 2FA | limited (persistence only) |
| 10 | CloudFire (Workspace) | limited (Workspace); out (consumer) |
| 11 | OAuth consent phishing (FBI) | stopped/limited on Workspace/M365; out for consumer |
| 12 | Infostealers/replay | out; limited after the fact |
| 13 | iCloud takeover | out of reach |
| 14 | SIM swap | out of reach |
| 15 | $282M wallet | out of reach |
| 16 | Wallet drainers | out of reach |
| 17 | Mixpanel | out of reach |

Count: 17 incidents. None is cleanly "would have stopped it": every "stopped" case still leaves a window between attacker action and detection. Roughly 6 of 17 are genuinely addressable (limit damage), 11 are out of reach.

## Synthesis

Features that cover the most incidents (ranked by incidents touched)
1. **New OAuth/app grant alert + one-click revoke** (#3, #4, #11, #10, #12 persistence). Workspace/M365 only; consumer accounts have no list API, so fall back to a guided checklist link.
2. **Mail rule and forwarding watcher** (#7, #8, #9, #10, BEC generally). Highest signal-to-noise: delete-all, move-to-RSS/archive, external forward, special-character rule names. Works on consumer Gmail and Outlook.com too.
3. **New MFA method / recovery email or phone change** (#4, #8, #13-as-checklist). Rare event, high fidelity (Mandiant says so). Works for Entra and Workspace admin; not for iCloud.
4. **Sign-out-everywhere + token revoke on trigger** (#7, #8, #10, #12). Needs admin/Graph scope; consider the Mini Shai-Hulud dead-man's switch before auto-revoking developer tokens.
5. **New device registration / new session from new ASN** (#7, #8, #9, #12). Needs Entra P1 or Workspace admin Reports.
6. **GitHub: new public repo, new self-hosted runner/workflow, new SSH/deploy key, PAT rotate prompt** (#5, #6). Settings-level only; personal security log has no API.
7. **Config posture checks**: device-code flow blocked, passkeys enrolled, SMS 2FA retired, carrier port-out PIN, Advanced Data Protection, offline photo copy (#7, #9, #13, #14). These prevent more than any detection does.

What no account-settings tool can prevent
- Theft at the provider or vendor with a legitimate pre-existing grant (#1, #2, #3b, #6, #17).
- Malware on the device (#12), including a watcher running on the same infected machine.
- Data copied before any setting changed (first minutes of an AiTM or consent-phish session).
- SIM swaps and anything at carriers (#14).
- Seed-phrase and wallet-signature scams (#15, #16).
- iCloud/Apple (#13): no API, no lock, and this tool does not read the notification emails.
- The user clicking Allow: the tool detects afterwards, not before.
