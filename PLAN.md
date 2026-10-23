# PHP2Shell Shield — v1 Plan

**Name:** PHP2Shell Shield
**Tagline:** Block the exploit. Protect your site.
**Type:** Distributable WordPress plugin (install a zip, click one button)
**License/distribution:** Open source — WordPress.org + GitHub, plus my own and client sites
**Date:** 2026-10-23
**Status:** Plan only. Nothing built yet.

---

## 1. The one-line pitch

A shield for WordPress sites that **cannot or will not update PHP**, because the
owner is afraid an upgrade will break the site. It cuts the risk of **PHP2Shell**
(CVE-2026-109618 / CVE-2026-109619) and a growing list of other current threats,
without touching the site's theme, plugins, or PHP version.

It buys time. It is not a cure.

---

## 2. Who this is for

- Site owners stuck on old or mid PHP (5.4 → 8.4) who won't upgrade because "it works, don't touch it."
- Agencies with dozens of client sites they can't all upgrade this week.
- People on cheap shared hosting who can't rebuild their stack.
- Non-technical users. They install a zip, see a traffic light, press one button.

These are exactly the people the NSA notice was aimed at: *"if an immediate update
is not feasible... take the system offline until it can be fully mitigated."* This
plugin is the middle ground between "do nothing" and "take it offline."

---

## 3. The honesty rule (non-negotiable)

The in-product UI, the readme, and the settings screen all say the same thing in plain words:

> **This is risk reduction, not a true fix.** The only real fix for PHP2Shell is
> updating PHP to a fixed version. This plugin lowers your chance of being hit and
> tells you if you already were. It cannot make an unpatched server perfectly safe.

The marketing banner can say "Block the exploit" — the edge rule and lockdown genuinely
can block it. But **inside the plugin**, the best status we ever show is
**"Shielded — still update PHP when you can,"** never a flat "you are safe." Selling
false safety to non-technical people on broken stacks is the one thing that would make
this plugin harmful instead of helpful.

---

## 4. Affected versions (what the PHP2Shell pack flags)

- **Vulnerable:** all PHP from **5.4 through anything below the fixed releases**, which explicitly
  **includes PHP 8.2** (8.2.0–8.2.34), 8.3 below 8.3.36, 8.4 below 8.4.27, 8.5 below 8.5.12, and
  every 5.x / 7.x / 8.0 / 8.1 build.
- **Fixed releases:** **8.2.35**, 8.3.36, 8.4.27, 8.5.12. Some hosts backport the fix while keeping
  the old version number — the plugin handles that (see §6.2).
- **Note for us:** our own cPanel servers run PHP 8.2, so they are in range and need 8.2.35 + a
  PHP-FPM restart regardless of this plugin.

---

## 5. The core design constraint (why a normal plugin fails)

PHP2Shell fires **while PHP is still reading the incoming request** — before WordPress,
before any plugin, before any PHP code we could write, runs. So:

- A plugin that tries to "block PHP2Shell" with PHP code is already too late.
- The defenses have to live where the request is handled **before PHP starts**:
  the **edge** (Cloudflare), the **web server** (`.htaccess` / nginx config), and PHP's own
  pre-execution config (`.user.ini`).

WordPress is only the **installer and control panel**. The actual shield is edge + server-config
files the plugin writes and watches. Those keep working even if the plugin is disabled or deleted.

```
Request ─▶ [ Cloudflare rule ] ─▶ [ .htaccess / nginx ] ─▶ [ PHP + .user.ini ] ─▶ WordPress
            edge filter (5.5)       server filter (5.5)       pre-PHP shield (5.3)   control panel only
```

---

## 6. What's in v1 (seven components)

### 6.1 Rule-pack engine (the spine)
With a new critical bug landing every few hours ("Black October"), a plugin hard-coded for one
bug is stale within a week. v1 is an **engine that loads signed rule packs**, not a one-bug fix.

- A rule pack = a small **signed** JSON file describing one threat: affected PHP/server versions,
  the mitigations (edge rule, server rule, ini settings), what to scan for, and plain-language advice.
- **Signature-verified.** The plugin writes server and edge config, so a poisoned pack would be a
  disaster — it refuses any unsigned or tampered pack. (This is exactly the UpdraftCentral failure
  mode: a trusted update channel used to push malicious change.)
- Updates over HTTPS from our server, or installable by zip for sites with no outbound access.
  New NSA/CISA guidance ships as a pack, not a new plugin release.
- **v1 ships with the PHP2Shell pack built in.** WP2Shell, UpdraftCentral, NGINX packs follow.

### 6.2 Host & exposure detection (setup wizard + traffic light)
Runs at setup and on demand. Auto-detects the environment and reports in plain language:
- **Server type:** Apache, LiteSpeed, NGINX, IIS, or unknown — and **how PHP runs** (FPM / CGI /
  Apache module / LiteSpeed SAPI). This drives which shield method the plugin uses.
- PHP version, and whether the active mitigations are **actually in effect** (verified on a real
  request, not assumed).
- Whether Cloudflare (or another proxy) is in front.
- A single status: **Exposed / Shielded / Needs host action**.
- **Backport-aware:** a backported fix keeps the old version number, so instead of a false alarm it
  says *"your version looks old but your host may have backported the fix — here's how to check."*

### 6.3 Pre-PHP settings (the primary shield for the "won't upgrade" user)
Writes PHP's own official stopgap settings where they take effect before PHP processes the request:
- `session.upload_progress.enabled=0` (mitigates CVE-2026-109619)
- `memory_limit=-1` (mitigates CVE-2026-109618)

Details:
- Written to `.user.ini` (FPM/CGI), `.htaccess` `php_value` (Apache module), or the right place for
  the detected SAPI. On NGINX/other it emits a snippet for the host (see §6.5).
- **Verified**, not assumed: after writing, a tiny probe confirms on the next request that the setting
  is live. If the host locks these settings, it says so and points to the host.
- Clear warning about `memory_limit=-1`: one runaway script can exhaust server RAM. The user sees the
  trade-off in plain words before enabling. PHP's own recommendation, but the owner decides.
- Fully reversible — one "undo" restores the originals from a backup the plugin kept.

### 6.4 Lockdown switch (the "take it offline" button, done gently)
Our version of the NSA's "take the system offline," but one click and reversible:
- Visitors get a static maintenance page; PHP is only reachable from the owner's own IP.
- Applied at the server/edge, so it works **before PHP starts** — the only place that can stop
  PHP2Shell reaching the vulnerable code.
- The panic button for the "my site might break" user: flip it, the site is cold-stored and safe,
  nothing in their stack changed, flip it back once patched or confirmed clean.

### 6.5 Edge + server request filter (now core in v1)
Refuses the kind of request PHP2Shell rides in on, **before the server hands it to PHP**:
- **Cloudflare:** via the Cloudflare API (token entered by the owner), the plugin pushes a WAF rule so
  bad requests are dropped at Cloudflare and never reach the server at all — the strongest layer.
- **Apache / LiteSpeed:** equivalent rules in `.htaccess`.
- **NGINX / IIS / other:** the plugin can't write there, so it **generates a copy-paste snippet** and
  shows exactly where to put it (host-side).
- Rules come from the active rule pack, with an **allowlist** so legitimate uploads (media, forms,
  checkout) still work. Allowlist is editable in the UI.

### 6.6 Breach check (assume some are already hit)
PHP2Shell runs as the web user and exploitation started before the patch, so a share of sites are
already compromised. The check looks for it:
- WordPress **core** files vs WordPress.org checksums.
- Each **plugin's** files vs the official WordPress.org copy (catches a backdoored plugin — the
  UpdraftCentral pattern).
- PHP files in `/uploads`, unknown admin users, new/odd cron jobs, and recently modified
  `.htaccess` / `.user.ini` (a classic backdoor hiding spot — and files this plugin owns, so it
  fingerprints them and alerts on any change it didn't make).
- **Remote-key audit:** lists every remote-management connection that is itself a master key to the
  site — UpdraftCentral, ManageWP, MainWP, InfiniteWP, Jetpack — and lets the owner revoke each.
- v1 **reports**; it does not auto-delete (too dangerous without a human looking).

### 6.7 Secrets reset (because memory leaked)
PHP2Shell can leak memory containing passwords and API keys:
- One click rotates the WordPress auth keys/salts in `wp-config.php` (logs everyone out — warned first).
- A checklist for what the plugin can't rotate itself: database password, hosting panel password,
  SMTP and payment API keys.

---

## 7. Explicitly NOT in v1

- **The multi-site dashboard** (manage many sites from one place). Most useful for agencies, but it's
  exactly the stolen-key risk the UpdraftCentral attack exploited. Build it later, and so a stolen
  dashboard key can only **read reports**, never write config or install code.
- Auto-deletion of malware (report only in v1).
- Automated PHP upgrades (out of scope — the thing these users are avoiding).

---

## 8. Open-source + signing model (settled)

Open source means the verification code is public, so the signing has to be done right:
- A **dedicated PHP2Shell Shield signing keypair** — *not* reused from Fatoura/Destina (keeps blast
  radius separate).
- The **public key ships inside the plugin**; the **private key stays offline** with you and signs
  each rule pack. The private key never goes in the GitHub repo.
- Packs verify against the bundled public key before the plugin will apply them. This is what makes
  an open-source auto-updating security plugin safe to trust.

**WP.org vs GitHub split:** GitHub carries the full version. The WordPress.org version may need to be
more conservative to pass review (writing server config, `memory_limit=-1`, and "security" claims all
draw scrutiny) — e.g. more explicit opt-in prompts. Same codebase, a compliance flag, not a fork.

---

## 9. Plugin structure (sketch)

```
php2shell-shield/
├── php2shell-shield.php         # bootstrap, header, activation/deactivation
├── readme.txt                   # WordPress.org format; honesty rule up top
├── includes/
│   ├── class-engine.php          # rule-pack loader + signature verify
│   ├── class-detect.php          # 6.2 server/SAPI/PHP/proxy detection
│   ├── class-settings-writer.php # 6.3 .user.ini/.htaccess writer + verifier + backups
│   ├── class-lockdown.php        # 6.4 lockdown on/off
│   ├── class-edge.php            # 6.5 Cloudflare API + .htaccess + snippet generator
│   ├── class-scan.php            # 6.6 core/plugin checksums, uploads, users, cron
│   ├── class-keys-audit.php      # 6.6 remote-management connections
│   ├── class-secrets.php         # 6.7 salt rotation + checklist
│   └── compat.php                # PHP 5.4 shims (see §11)
├── packs/
│   ├── php2shell.pack.json        # ships built-in
│   └── php2shell.pack.sig
├── admin/                        # control-panel UI (traffic light + buttons + setup wizard)
└── assets/                       # banner, icon, screenshots
```

A rule pack, roughly:
```json
{
  "id": "php2shell",
  "cve": ["CVE-2026-109618", "CVE-2026-109619"],
  "affects": { "php": "<8.2.35 || (>=8.3 <8.3.36) || (>=8.4 <8.4.27) || (>=8.5 <8.5.12)" },
  "mitigations": {
    "ini":  { "session.upload_progress.enabled": "0", "memory_limit": "-1" },
    "edge": { "block": "multipart-upload-on-non-upload-paths", "allowlist_default": true }
  },
  "scan": { "uploads_php": true, "modified_config": true },
  "advice": "Update PHP to a fixed version. Until then, enable the shield below.",
  "severity": "critical"
}
```

---

## 10. Protecting the plugin itself (master-hacker view)

The plugin writes server/edge config and holds clean-up keys, so it's a target.
- **Signed rule packs only.** Unsigned or altered pack → refused. (The UpdraftCentral lesson.)
- **The shield survives the plugin.** Edge + server-file layers are independent of the plugin, so
  disabling/deleting it doesn't drop the shield — good against an attacker who kills security plugins.
- **The plugin owns and fingerprints `.htaccess` / `.user.ini`,** so a backdoor slipped into those is
  flagged on the next scan.
- **No "read it all" remote control in v1.** No outbound master key for anyone to steal.
- **Cloudflare token stored encrypted**, used only from the server, never exposed to the browser.
- **Least privilege:** clean-up/secrets actions require a logged-in admin and a fresh nonce, never a
  replayable URL.

---

## 11. Compatibility constraints

- **Runs on PHP 5.4** (oldest affected) — no arrow functions, no `??`, no typed properties in our own
  code. `compat.php` holds the shims.
- **Apache & LiteSpeed:** full feature set (they read `.htaccess`).
- **NGINX / IIS:** detection + verified status + generated snippets; honest that it can't self-install.
- **Cloudflare:** full edge rule via API when a token is provided.
- **No shell / no exec** (many of these hosts disable it) — everything via PHP file + HTTP APIs.
- **WordPress 5.0+** for the admin UI.

---

## 12. Build & test approach

- `_src` + `build.sh` → versioned zip (`php2shell-shield-vX.Y.Z.zip`), same shape as your Fatoura/Arida patches.
- Old-PHP test matrix (throwaway containers/VMs): PHP 5.6, 7.4, 8.1, **8.2**, 8.3 — confirm writer +
  verifier + detection behave per SAPI.
- `test.sh`: pack-signature check, settings-writer round-trip (write → verify → undo), edge snippet
  generation, scanner against a known-dirty fixture site.
- Every delivery gets a new version + archive (never overwrite a sent zip).

---

## 13. Milestones (pause after each, per your usual rhythm)

- **M0 — Skeleton + detection:** plugin header, admin page, setup wizard, host/SAPI/PHP/proxy detection,
  exposure traffic light (6.2). Read-only, no writes yet.
- **M1 — The shield:** pre-PHP settings writer + verifier + undo (6.3), honesty UI.
- **M2 — Engine:** rule-pack loader + signature verify (6.1), PHP2Shell pack built in, signing keypair set up (§8).
- **M3 — Edge + lockdown:** Cloudflare rule + `.htaccess` + nginx snippet (6.5), lockdown switch (6.4).
- **M4 — Breach check:** core/plugin checksums, uploads/users/cron scan, remote-key audit (6.6).
- **M5 — Secrets:** salt rotation + checklist (6.7).
- **M6 — Package:** readme, build.sh, versioned zip, GitHub repo, WP.org-compliant build, old-PHP matrix test.
- *(Later: WP2Shell / UpdraftCentral / NGINX packs, then the multi-site dashboard.)*

---

## 14. Decisions settled 2026-10-23

| Question | Decision |
|---|---|
| Name | **PHP2Shell Shield** (banner + tagline already made) |
| Distribution | Open source — WordPress.org + GitHub, plus my own and client sites |
| Hosts | **All server types**, auto-detected at setup; full shield on Apache/LiteSpeed + Cloudflare, snippets for NGINX/IIS |
| Cloudflare | **Yes — edge rule built into v1** (now component 6.5) |
| PHP 8.2 | **Included as affected** (fix is 8.2.35) |
| Signing key | Dedicated keypair; public key in plugin, private key offline (not reused from other projects) |
