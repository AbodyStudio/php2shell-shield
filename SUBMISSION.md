# WordPress.org submission package — PHP2Shell Shield

Everything needed to submit to the WordPress.org plugin directory, plus the
compliance work to do **before** submitting. (This file is a dev doc; it is not
shipped in the plugin zip.)

---

## 1. Snapshot

| Field | Value |
|---|---|
| Plugin name | **PHP2Shell Shield** |
| Proposed slug | `php2shell-shield` |
| Current version | 1.3.1 |
| License | GPL-2.0-or-later |
| Requires at least | WordPress 4.0 |
| Requires PHP | 5.4 |
| Tested up to | (set to the current WordPress version at submission time) |
| Author | AbodyStudio — https://abodystudio.com |
| Submit at | https://wordpress.org/plugins/developers/add/ |

---

## 2. Short description (≤ 150 characters)

> Reduce the risk of the PHP2Shell exploit on sites that can't update PHP yet, and get safely onto a fixed PHP version. A shield, not a cure.

Alternates:
- `Risk reduction for the PHP2Shell PHP RCE on sites that can't update PHP yet — plus tools to upgrade PHP safely. A shield, not a cure.`
- `Protect WordPress from the PHP2Shell exploit while you're on an old PHP, check upgrade-readiness, and move to a fixed PHP version.`

---

## 3. Full description (the pitch)

The polished description already lives in `readme.txt` (the `== Description ==`
section). It leads with the honesty line, explains why defences must act before
PHP runs, lists the features, and discloses every external service. Use that as
the directory listing text. Key beats:

- **The problem, in one line:** PHP2Shell (CVE-2026-109618 / CVE-2026-109619) is
  a critical PHP-core RCE. The real fix is updating PHP — but many site owners
  can't or won't right away.
- **Why this is different:** the bug fires *before WordPress loads*, so the
  plugin puts its defences where the request is handled before PHP runs (edge,
  web server, `.user.ini`). WordPress is only the control panel.
- **What you get:** detection, a one-click shield, an edge request filter,
  lockdown, a breach check, a remote-key audit, a secrets reset, and tools to
  check upgrade-readiness and (on cPanel) switch PHP safely.
- **The honest promise:** it never claims more safety than it delivers — the
  best status it shows is "Shielded — still update PHP when you can."

---

## 4. Tags

`security, php2shell, hardening, vulnerability, cve`

---

## 5. Note to the Plugin Review Team (paste into the submission message)

> **What it does:** PHP2Shell Shield helps WordPress sites running an affected,
> un-updatable PHP version reduce their exposure to the PHP2Shell remote code
> execution flaw (CVE-2026-109618 / CVE-2026-109619), and then move onto a fixed
> PHP version safely. It is framed throughout as risk reduction, not a fix — it
> never claims to make an unpatched server safe.
>
> **Server-config changes are user-initiated, reversible, and backed up.** The
> plugin can write PHP's own recommended stopgap settings to `.user.ini` or
> `.htaccess`, an optional request-filter block to `.htaccess`, and (opt-in) a
> lockdown block. Every write happens only on an explicit admin action with a
> nonce, is confined to a clearly marked block, keeps a backup, and has a
> one-click undo. Directives written to `.htaccess` are wrapped in `IfModule`
> guards so they cannot take a site down.
>
> **`memory_limit = -1`** is one of the two stopgap settings. It is PHP's own
> published recommendation for this CVE; it is opt-in, disclosed in the UI with
> its trade-off, and reversible.
>
> **Secrets reset / wp-config.php:** an explicit admin action can rotate the
> WordPress salts in `wp-config.php`. It backs the file up first, rewrites only
> the salt lines, validates the result, and writes atomically.
>
> **PHP version switch (cPanel EA4):** where a site selects PHP via an
> `.htaccess` handler, an explicit, confirmed admin action can change it; it
> backs up `.htaccess`, verifies the site comes up on the new version, and
> automatically reverts if it does not. Elsewhere it only links to cPanel's
> MultiPHP Manager.
>
> **External services (all disclosed in the readme, all user-initiated):**
> api.wordpress.org (official file checksums for the breach check), and — only
> if the user connects it — api.cloudflare.com (to manage a firewall rule in the
> user's own zone). No data is sent anywhere else and the plugin does not phone
> home.
>
> **For this .org submission we have disabled the plugin's own update channel**
> (it normally self-updates from our signed GitHub releases) so that updates come
> exclusively from WordPress.org, per the guidelines. Threat-definition "rule
> packs" are signed JSON **data** (not code) and the plugin ships and runs with a
> built-in pack; remote pack fetching is disabled in the .org build.
>
> No obfuscated code, no external/remote PHP execution, GPL-2.0-or-later
> throughout, and all output is escaped / input sanitised / actions nonced. Happy
> to adjust anything the team flags.

---

## 6. Compliance status (Plugin Check)

**Submit the `.org` build:** `./build.sh dotorg` → `dist/php2shell-shield-vX.Y.Z-wporg.zip`.
It omits the self-updater; the main file loads that file only if present.

Done (v1.3.2):
- [x] **Self-updater removed from the .org build** (the sev-9 "Plugin Updater
      detected" blocker). `includes/class-updater.php` is excluded by
      `build.sh dotorg`; nothing alters WordPress update routines in that build.
- [x] **Direct-access guard** (`if ( ! defined( 'ABSPATH' ) ) { exit; }`) on
      every file.
- [x] **Escaping / sanitising / nonces** — `$_SERVER` reads unslashed +
      sanitised; every admin action is nonce-checked; the one SVG echo is a
      fixed, safe string (documented).
- [x] **WordPress APIs** — cURL replaced with the HTTP API; `mt_rand`/`mt_srand`
      replaced with `wp_rand`; `json_encode` → `wp_json_encode`.
- [x] **Direct filesystem ops documented** — the plugin must make atomic,
      credential-free writes to server config and roll them back, which
      `WP_Filesystem` cannot guarantee; these calls carry inline `phpcs:ignore`
      with that justification. (Only `is_writable`/`chmod`/`mkdir`/`rename`, the
      ones Plugin Check flags.)

Still to do before uploading:
- [ ] **Set `Tested up to:`** to the current WordPress version.
- [ ] **Add the directory assets** (section 7) and a `== Screenshots ==` readme
      section.
- [ ] Run the readme through the official validator
      (wordpress.org/plugins/developers/readme-validator/).
- [ ] The signing **private key is already out of every zip** — no action needed.

Nice-to-have: an `uninstall.php` that cleans options (already present), and a
clear FAQ entry about the edge filter possibly affecting forms (already present).

---

## 7. Directory assets to prepare (SVN `assets/` folder, not in the zip)

| Asset | Size | Have it? |
|---|---|---|
| Plugin icon | `icon-128x128.png`, `icon-256x256.png` (or `icon.svg`) | Can generate from `assets/shield.svg` |
| Banner | `banner-772x250.png`, `banner-1544x500.png` | Adapt `assets/banner.png` |
| Screenshots | `screenshot-1.png`, `screenshot-2.png`, … (match `== Screenshots ==` in readme) | Have real ones in repo `assets/` |

Add a `== Screenshots ==` section to `readme.txt` with one caption per image,
in the same order as the numbered files.

---

## 8. Likely reviewer questions & answers

- **"Why write to `.htaccess` / `.user.ini` / `wp-config.php`?"** → It's the
  only place this pre-PHP exploit can be mitigated; all writes are user-initiated,
  marked, backed up, and reversible.
- **"`memory_limit=-1` is risky."** → It's PHP's own recommendation for this CVE,
  opt-in, disclosed, reversible.
- **"Does it phone home / self-update?"** → Not in the .org build; updates come
  from .org, and the only external calls are api.wordpress.org (checksums) and
  the user's own Cloudflare, both disclosed.
- **"Changing the PHP version from a plugin?"** → Opt-in, confirmed, cPanel-only,
  with backup + automatic revert; otherwise it just links to MultiPHP Manager.

---

## 9. After approval

- Keep the GitHub repo as the canonical dev home; push releases to the .org SVN
  `trunk` + `tags/` and update `Stable tag`.
- The GitHub build can keep its signed self-updater for users who install from
  GitHub; the .org build omits it. Same codebase, one compliance flag.
