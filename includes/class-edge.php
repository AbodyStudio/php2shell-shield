<?php
/**
 * Edge request filter for PHP2Shell Shield.
 *
 * CVE-2026-109619 is reached through multipart/form-data uploads (via
 * session.upload_progress). PHP's own advice for sites that do not need it is
 * to block multipart form data at the front end. This filter does exactly
 * that: it refuses multipart POSTs EXCEPT on an allowlist of paths that
 * legitimately handle uploads (wp-admin, login, cron, plus anything the owner
 * adds).
 *
 * It is surface reduction, not a precise exploit signature, and it CAN affect
 * front-end forms and uploads — so it is opt-in and the allowlist is editable.
 * The same rule can be applied three ways: Apache/LiteSpeed .htaccess (written
 * here), Cloudflare (via P2S_Cloudflare), or an nginx snippet (generated here).
 *
 * WordPress-independent so it can be tested from the CLI.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Edge {

	const LABEL = 'Filter';

	/** @var P2S_Files */
	protected $files;

	/** @var array Detection report. */
	protected $report;

	public function __construct( $base = null, $report = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd();
		}
		$this->files  = new P2S_Files( $base );
		$this->report = is_array( $report ) ? $report : array();
	}

	/* ---- allowlist ----------------------------------------------------- */

	public function default_allowlist() {
		return array( '/wp-admin/', '/wp-login.php', '/wp-cron.php', '/wp-json/' );
	}

	public function allowlist() {
		$a = p2s_opt_get( 'p2s_edge_allow' );
		if ( is_array( $a ) ) {
			return $a;
		}
		return $this->default_allowlist();
	}

	/**
	 * Store a cleaned allowlist. Each entry is a path prefix starting with "/".
	 *
	 * @param array $list Raw list.
	 * @return array The cleaned list that was stored.
	 */
	public function set_allowlist( $list ) {
		$clean = array();
		if ( is_array( $list ) ) {
			foreach ( $list as $p ) {
				$p = trim( (string) $p );
				if ( '' === $p ) {
					continue;
				}
				if ( '/' !== substr( $p, 0, 1 ) ) {
					$p = '/' . $p;
				}
				// Keep it a simple path: no spaces, no newlines, no wildcards.
				$p = preg_replace( '/[\s]+/', '', $p );
				if ( '' !== $p && ! in_array( $p, $clean, true ) ) {
					$clean[] = $p;
				}
			}
		}
		if ( empty( $clean ) ) {
			$clean = $this->default_allowlist();
		}
		p2s_opt_set( 'p2s_edge_allow', $clean );
		return $clean;
	}

	/* ---- rule bodies --------------------------------------------------- */

	/** Escape a path prefix for a RewriteCond regex (anchored at start). */
	protected function rx( $path ) {
		return '^' . preg_quote( $path, '' );
	}

	/**
	 * The .htaccess lines (mod_rewrite) for the multipart filter.
	 *
	 * @return array
	 */
	public function htaccess_lines() {
		$lines   = array();
		$lines[] = '<IfModule mod_rewrite.c>';
		$lines[] = 'RewriteEngine On';
		$lines[] = 'RewriteCond %{REQUEST_METHOD} =POST';
		$lines[] = 'RewriteCond %{CONTENT_TYPE} multipart/form-data [NC]';
		foreach ( $this->allowlist() as $path ) {
			$lines[] = 'RewriteCond %{REQUEST_URI} !' . $this->rx( $path ) . ' [NC]';
		}
		$lines[] = 'RewriteRule ^ - [F]';
		$lines[] = '</IfModule>';
		return $lines;
	}

	/**
	 * A Cloudflare rule expression for the same filter.
	 *
	 * @return string
	 */
	public function cf_expression() {
		$parts   = array();
		$parts[] = 'http.request.method eq "POST"';
		$parts[] = 'any(lower(http.request.headers["content-type"][*])[*] contains "multipart/form-data")';
		foreach ( $this->allowlist() as $path ) {
			$parts[] = 'not starts_with(http.request.uri.path, "' . addslashes( $path ) . '")';
		}
		return '(' . implode( ' and ', $parts ) . ')';
	}

	/**
	 * An nginx snippet (for the host to place inside the server block).
	 *
	 * @return string
	 */
	public function nginx_snippet() {
		$allow = $this->allowlist();
		$out   = array();
		$out[] = '# PHP2Shell Shield — add inside your server { } block, then reload nginx.';
		$out[] = '# Blocks multipart/form-data POSTs except on allowlisted paths.';
		$out[] = 'set $p2s_block 0;';
		$out[] = 'if ($request_method = POST) { set $p2s_block "${p2s_block}1"; }';
		$out[] = 'if ($http_content_type ~* multipart/form-data) { set $p2s_block "${p2s_block}2"; }';
		foreach ( $allow as $path ) {
			$out[] = 'if ($uri ~* "^' . $path . '") { set $p2s_block "${p2s_block}9"; }';
		}
		$out[] = '# Block only when POST(1) + multipart(2) and no allow(9) matched:';
		$out[] = 'if ($p2s_block = "012") { return 403; }';
		return implode( "\n", $out );
	}

	/* ---- apply / remove ------------------------------------------------ */

	/** Can we write the .htaccess filter here? (Apache/LiteSpeed.) */
	public function can_write_htaccess() {
		$type = isset( $this->report['server']['type'] ) ? $this->report['server']['type'] : '';
		if ( ! in_array( $type, array( 'apache', 'litespeed' ), true ) ) {
			return false;
		}
		return $this->files->writable( '.htaccess' );
	}

	public function enable_htaccess() {
		if ( ! $this->can_write_htaccess() ) {
			return array( 'ok' => false, 'reason' => 'cannot_write', 'snippet' => $this->nginx_snippet() );
		}
		$content = $this->files->read( '.htaccess' );
		if ( null === p2s_opt_get( 'p2s_edge_backup' ) ) {
			p2s_opt_set( 'p2s_edge_backup', array( 'existed' => $this->files->exists( '.htaccess' ) ? 1 : 0 ) );
		}
		$new = $this->files->set_block( $content, $this->htaccess_lines(), '.htaccess', self::LABEL );
		if ( ! $this->files->write( '.htaccess', $new ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed', 'snippet' => $this->nginx_snippet() );
		}
		p2s_opt_set( 'p2s_edge', array( 'active' => 1, 'at' => time() ) );
		return array( 'ok' => true );
	}

	public function disable_htaccess() {
		$content  = $this->files->read( '.htaccess' );
		$stripped = $this->files->strip_block( $content, self::LABEL );
		$backup   = p2s_opt_get( 'p2s_edge_backup' );
		if ( is_array( $backup ) && empty( $backup['existed'] ) && '' === trim( $stripped ) ) {
			$this->files->delete( '.htaccess' );
		} else {
			$this->files->write( '.htaccess', $stripped );
		}
		p2s_opt_set( 'p2s_edge', array( 'active' => 0 ) );
		p2s_opt_delete( 'p2s_edge_backup' );
		return array( 'ok' => true );
	}

	public function is_active() {
		$s = p2s_opt_get( 'p2s_edge' );
		return ( is_array( $s ) && ! empty( $s['active'] ) );
	}
}
