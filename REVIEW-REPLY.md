# Reply to the WordPress.org plugin review team

> Paste the block below into your reply on the existing review thread.
> Before sending: (1) add the DNS TXT record (see note under "Ownership"),
> (2) make the TXT value match the exact token in the reviewer's email,
> (3) confirm the requested slug wording.

---

Hello, and thank you for the review. I've addressed every point.

**Name / slug (trademark).** I've renamed the plugin to **PHP Defender – Old PHP Versions Shield**. The name and slug no longer contain the coined vulnerability name. Requested slug: **`php-defender`** (if that one is unavailable, `old-php-exploit-shield` works for me). The vulnerability is now only referred to descriptively — by its common name alongside its CVE IDs — in the readme text, so people can still tell what the plugin defends against.

**Ownership.** My WordPress.org username is **`abodystudios`**, which now matches the `Contributors` line in the readme. To confirm I control the author domain, I have added the DNS **TXT** record you requested to **abodystudio.com**.

**Description formatting.** The stray quotation marks were mis-encoded em dashes. They are fixed, and I re-checked the rendered output.

**Auth keys/salts backup.** The pre-rotation backup of the `wp-config.php` keys/salts is now stored in the database (a plugin option), **not** in the uploads folder. The plugin no longer writes privileged data to the uploads or plugin directories.

**Allowlist input sanitisation.** Every allowlist path is now sanitised, normalised, and length-capped per entry before anything is written to server config.

**Prefixes.** All PHP prefixes are now 4+ characters and unique to the plugin: functions `phpdef_`, classes `Phpdef_`, constants `PHPDEF_`, options `phpdef_` (previously the 3-character `p2s` / `P2S`).

**Requires PHP.** Raised to **7.0**.

**Bundled key file.** The bundled key is a *public* key used only to verify the plugin's signed rule packs — it can verify signatures, never create them. It now ships as `packs/signing-key.php` (a PHP file that returns the key) rather than a bare `.pub` file. The private signing key is never committed or shipped.

I'm happy to make any further changes you'd like. Thank you again for your time.

AbodyStudio
