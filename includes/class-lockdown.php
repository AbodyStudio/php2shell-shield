<?php
/**
 * Lockdown switch for PHP2Shell Shield — the "take it offline" button.
 *
 * Writes an .htaccess block that denies all access except from the owner's
 * IP(s), and serves a static maintenance page to everyone else. Because the
 * deny happens at the web server before PHP runs, it genuinely stops PHP2Shell
 * from reaching the vulnerable code — unlike anything done in PHP.
 *
 * Important Cloudflare caveat: behind Cloudflare the server sees Cloudflare's
 * IPs, not the visitor's, so server-level IP rules are unreliable there. The
 * admin layer detects this and recommends the Cloudflare-side lockdown instead.
 *
 * WordPress-independent so it can be tested from the CLI.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'P2S_STANDALONE' ) ) {
	exit;
}

class P2S_Lockdown {

	const LABEL = 'Lockdown';
	const PAGE  = 'p2s-maintenance.html';

	/** @var P2S_Files */
	protected $files;

	public function __construct( $base = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd();
		}
		$this->files = new P2S_Files( $base );
	}

	/**
	 * .htaccess lines that allow only the given IPs and send everyone else to
	 * the maintenance page. Covers both Apache 2.4 (authz_core) and 2.2.
	 *
	 * @param array $ips Allowed IPs.
	 * @return array
	 */
	public function htaccess_lines( $ips ) {
		$lines = array();

		// Apache 2.4+
		$lines[] = '<IfModule mod_authz_core.c>';
		$lines[] = '  <RequireAny>';
		foreach ( $ips as $ip ) {
			$lines[] = '    Require ip ' . $ip;
		}
		$lines[] = '  </RequireAny>';
		$lines[] = '</IfModule>';

		// Apache 2.2
		$lines[] = '<IfModule !mod_authz_core.c>';
		$lines[] = '  Order deny,allow';
		$lines[] = '  Deny from all';
		foreach ( $ips as $ip ) {
			$lines[] = '  Allow from ' . $ip;
		}
		$lines[] = '</IfModule>';

		// Let everyone reach the maintenance page itself.
		$lines[] = '<Files "' . self::PAGE . '">';
		$lines[] = '  <IfModule mod_authz_core.c>';
		$lines[] = '    Require all granted';
		$lines[] = '  </IfModule>';
		$lines[] = '  <IfModule !mod_authz_core.c>';
		$lines[] = '    Order allow,deny';
		$lines[] = '    Allow from all';
		$lines[] = '  </IfModule>';
		$lines[] = '</Files>';

		$lines[] = 'ErrorDocument 403 /' . self::PAGE;
		return $lines;
	}

	public function maintenance_html() {
		return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
			. "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
			. "<title>Temporarily offline</title>"
			. "<style>body{margin:0;background:#0b0f10;color:#fff;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
			. "display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center}"
			. ".box{max-width:480px;padding:32px}h1{font-size:24px;margin:16px 0 8px}p{color:#9aa0a6;line-height:1.5}"
			. ".m{font-size:40px}</style></head><body><div class=\"box\">"
			. "<div class=\"m\">&#128274;</div><h1>We&rsquo;ll be right back</h1>"
			. "<p>This site is temporarily offline for security maintenance. Please check back soon.</p>"
			. "</div></body></html>\n";
	}

	/**
	 * Turn lockdown on.
	 *
	 * @param array $ips Allowed IPs (owner).
	 * @return array
	 */
	public function enable( $ips ) {
		$ips = $this->clean_ips( $ips );
		if ( empty( $ips ) ) {
			return array( 'ok' => false, 'reason' => 'no_valid_ip' );
		}
		if ( ! $this->files->writable( '.htaccess' ) ) {
			return array( 'ok' => false, 'reason' => 'cannot_write' );
		}

		// Write the maintenance page first so the 403 document exists.
		if ( ! $this->files->write( self::PAGE, $this->maintenance_html() ) ) {
			return array( 'ok' => false, 'reason' => 'page_write_failed' );
		}

		$content = $this->files->read( '.htaccess' );
		if ( null === p2s_opt_get( 'p2s_lock_backup' ) ) {
			p2s_opt_set( 'p2s_lock_backup', array( 'existed' => $this->files->exists( '.htaccess' ) ? 1 : 0 ) );
		}
		$new = $this->files->set_block( $content, $this->htaccess_lines( $ips ), '.htaccess', self::LABEL );
		if ( ! $this->files->write( '.htaccess', $new ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed' );
		}
		p2s_opt_set( 'p2s_lock', array( 'active' => 1, 'ips' => $ips, 'at' => time() ) );
		return array( 'ok' => true, 'ips' => $ips );
	}

	public function disable() {
		$content  = $this->files->read( '.htaccess' );
		$stripped = $this->files->strip_block( $content, self::LABEL );
		$backup   = p2s_opt_get( 'p2s_lock_backup' );
		if ( is_array( $backup ) && empty( $backup['existed'] ) && '' === trim( $stripped ) ) {
			$this->files->delete( '.htaccess' );
		} else {
			$this->files->write( '.htaccess', $stripped );
		}
		$this->files->delete( self::PAGE );
		p2s_opt_set( 'p2s_lock', array( 'active' => 0 ) );
		p2s_opt_delete( 'p2s_lock_backup' );
		return array( 'ok' => true );
	}

	public function is_active() {
		$s = p2s_opt_get( 'p2s_lock' );
		return ( is_array( $s ) && ! empty( $s['active'] ) );
	}

	public function allowed_ips() {
		$s = p2s_opt_get( 'p2s_lock' );
		if ( is_array( $s ) && isset( $s['ips'] ) ) {
			return $s['ips'];
		}
		return array();
	}

	protected function clean_ips( $ips ) {
		$out = array();
		if ( ! is_array( $ips ) ) {
			$ips = array( $ips );
		}
		foreach ( $ips as $ip ) {
			$ip = trim( (string) $ip );
			if ( p2s_is_ip( $ip ) && ! in_array( $ip, $out, true ) ) {
				$out[] = $ip;
			}
		}
		return $out;
	}
}
