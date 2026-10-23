=== PHP2Shell Shield ===
Contributors: abodystudio
Tags: security, php2shell, hardening, vulnerability, cve
Requires at least: 4.0
Tested up to: 7.1
Requires PHP: 5.4
Stable tag: 1.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Risk reduction for the PHP2Shell exploit on sites that cannot update PHP yet. A shield, not a cure — the only real fix is updating PHP.

== Description ==

**This is risk reduction, not a true fix.** The only real fix for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619) is updating PHP to a fixed version
(8.2.35, 8.3.36, 8.4.27 or 8.5.12). This plugin is for sites that cannot do
that right away because an upgrade might break them. It lowers your chance of
being hit, tells you if you were already compromised, and gives you an
emergency switch — but it cannot make an unpatched server perfectly safe.

The PHP2Shell bug fires before WordPress loads, so a normal plugin cannot block
it with PHP code. This plugin instead places its defences where the request is
handled *before PHP runs*: at the edge (Cloudflare), at the web server
(.htaccess / nginx), and in PHP's own pre-execution config (.user.ini).
WordPress is only the control panel.

= What it does =

* **Detects** your PHP version, how PHP runs (FPM / CGI / mod_php / LiteSpeed),
  your web server, and whether Cloudflare is in front — and tells you plainly
  whether you are Exposed, Shielded, Patched, or need your host.
* **Shield**: one click writes PHP's own recommended stopgap settings to
  .user.ini or .htaccess, verifies they took effect, and undoes cleanly.
* **Edge filter**: blocks upload-style requests except on an allowlist, via
  .htaccess, Cloudflare, or a generated nginx snippet.
* **Lockdown**: takes the site offline for everyone except your IP, before PHP
  runs, with a maintenance page. Instantly reversible.
* **Breach check**: compares core and plugin files against WordPress.org
  checksums, scans uploads for hidden PHP, and lists recent admin accounts.
* **Remote key audit**: finds remote-management connectors (UpdraftCentral,
  ManageWP, MainWP, InfiniteWP, Jetpack) and lets you cut any of them.
* **Secrets reset**: rotates your WordPress security keys so stolen sessions
  stop working, with a checklist of what you must change yourself.
* Threat definitions load from a **cryptographically signed** rule pack, so new
  guidance can ship without a plugin rebuild. Unsigned or tampered packs are
  refused.

== External services ==

This plugin contacts these services, only when you ask it to:

* **api.wordpress.org** — to fetch the official file checksums used by the
  breach check (core and plugin verification). Only the WordPress and plugin
  versions and your locale are sent. See https://wordpress.org/about/privacy/ .
* **api.cloudflare.com** — only if you connect a Cloudflare API token and deploy
  the edge rule. Your token and the rule are sent to manage a firewall rule in
  your own Cloudflare zone. See https://www.cloudflare.com/privacypolicy/ .
* **api.github.com** and **github.com** — to check for and download plugin
  updates from the project's GitHub Releases (this plugin is distributed on
  GitHub, not WordPress.org). Only the request to read the latest release and
  download the signed update is made. Every update is verified against the
  plugin's bundled signing key before it is installed. See
  https://docs.github.com/site-policy/privacy-policies/github-privacy-statement .

The plugin does not phone home and sends no data anywhere else.

== Installation ==

1. Upload the `php2shell-shield` folder to `/wp-content/plugins/`, or install
   the zip from Plugins → Add New → Upload.
2. Activate it.
3. Open **PHP2Shell Shield** in the admin menu and follow the status screen.

== Frequently Asked Questions ==

= Does this replace updating PHP? =

No. It reduces risk and buys time. Update PHP to a fixed version as soon as you
can; this plugin is for the gap until then.

= Will the shield break my site? =

The core shield (.user.ini / .htaccess settings) is PHP's own recommendation
and is safe on almost all sites; it is reversible. The **edge filter** can
affect front-end forms and uploads, so it is opt-in with an editable allowlist —
test your forms after turning it on.

= I am behind Cloudflare. Anything to know? =

Yes. Server-level IP rules see Cloudflare's IPs, not your visitors', so the
.htaccess lockdown may be unreliable behind Cloudflare. Use the Cloudflare
options instead; the plugin warns you about this.

== Support ==

By AbodyStudio — https://abodystudio.com

Questions, bug reports, or a vulnerability to report? Email
support@abodystudio.com or abodystudio@gmail.com, or open an issue at
https://github.com/AbodyStudio/php2shell-shield/issues .

== Changelog ==

= 1.1.1 =
* Added a GitHub auto-updater: updates now appear on the Plugins screen and install in one click, straight from the project's GitHub Releases.
* Every update is cryptographically verified (RSA-SHA256) against the plugin's bundled signing key before it is installed � an unsigned or tampered download is refused.

= 1.1.0 =
* Redesigned admin dashboard: modern, visual layout with the shield logo, a
  plain-language "How it works" section, icons on every panel, and clearer
  grouping (Protection / More protection / Check & recover / Details).
* Fixed the manual snippet boxes so the code is always clearly visible.
* The plugin's menu icon is now the PHP2Shell Shield shield.
* Broader WordPress compatibility (WordPress 4.0+).

= 1.0.0 =
* First stable release. Detection, one-click shield, edge filter (.htaccess /
  Cloudflare / nginx), lockdown, breach check, remote-key audit, secrets reset,
  and a signed rule-pack engine. Verified PHP 5.4+ compatible.

= 0.6.0 =
* Secrets reset: rotates the eight WordPress auth keys/salts safely, plus a
  checklist of secrets to change yourself.

= 0.5.0 =
* Breach check (core/plugin checksums, uploads scan, recent admins) and the
  remote access key audit.

= 0.4.0 =
* Edge request filter (.htaccess / Cloudflare / nginx) and the lockdown switch.

= 0.3.0 =
* Signed rule-pack engine with the PHP2Shell pack built in.

= 0.2.0 =
* One-click shield with backup, atomic writes, and verification.

= 0.1.0 =
* Environment detection and status dashboard.

== Upgrade Notice ==

= 1.0.0 =
First stable release. Update PHP to a fixed version when you can — this plugin
reduces risk, it is not a replacement for the patch.
