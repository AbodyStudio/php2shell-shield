<?php
/**
 * Edge request filter for AbodyStudio Shield.
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
 * here), Cloudflare (via Abody_Cloudflare), or an nginx snippet (generated here).
 *
 * WordPress-independent so it can be tested from the CLI.
 *
 * @package AbodyStudio_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Abody_Edge {

	const LABEL = 'Filter';

	/** @var Abody_Files */
	protected $files;

	/** @var array Detection report. */
	protected $report;

	public function __construct( $base = null, $report = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd();
		}
		$this->files  = new Abody_Files( $base );
		$this->report = is_array( $report ) ? $report : array();
	}

	/* ---- allowlist ----------------------------------------------------- */

	public function default_allowlist() {
		return array( '/wp-admin/', '/wp-login.php', '/wp-cron.php', '/wp-json/' );
	}

	public function allowlist() {
		$a = abody_opt_get( 'abody_edge_allow' );
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
				// Strict: keep only characters valid in a URL path. This strips
				// quotes, braces, spaces, regex metacharacters and anything else
				// that could break out of the generated .htaccess / nginx /
				// Cloudflare rule syntax these paths are interpolated into.
				$p = preg_replace( '#[^A-Za-z0-9/._~-]#', '', $p );
				$p = preg_replace( '#/{2,}#', '/', $p );
				if ( '' === $p ) {
					continue;
				}
				if ( '/' !== substr( $p, 0, 1 ) ) {
					$p = '/' . $p;
				}
				if ( strlen( $p ) > 200 ) {
					$p = substr( $p, 0, 200 );
				}
				if ( ! in_array( $p, $clean, true ) ) {
					$clean[] = $p;
				}
				if ( count( $clean ) >= 50 ) {
					break;
				}
			}
		}
		if ( empty( $clean ) ) {
			$clean = $this->default_allowlist();
		}
		abody_opt_set( 'abody_edge_allow', $clean );
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
		$out[] = '# AbodyStudio Shield — add inside your server { } block, then reload nginx.';
		$out[] = '# Blocks multipart/form-data POSTs except on allowlisted paths.';
		$out[] = 'set $abody_block 0;';
		$out[] = 'if ($request_method = POST) { set $abody_block "${abody_block}1"; }';
		$out[] = 'if ($http_content_type ~* multipart/form-data) { set $abody_block "${abody_block}2"; }';
		foreach ( $allow as $path ) {
			// Escape for the nginx regex even though set_allowlist() already
			// restricts the characters — defence in depth for the rule syntax.
			$out[] = 'if ($uri ~* "^' . preg_quote( $path, '' ) . '") { set $abody_block "${abody_block}9"; }';
		}
		$out[] = '# Block only when POST(1) + multipart(2) and no allow(9) matched:';
		$out[] = 'if ($abody_block = "012") { return 403; }';
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
		if ( null === abody_opt_get( 'abody_edge_backup' ) ) {
			abody_opt_set( 'abody_edge_backup', array( 'existed' => $this->files->exists( '.htaccess' ) ? 1 : 0 ) );
		}
		$new = $this->files->set_block( $content, $this->htaccess_lines(), '.htaccess', self::LABEL );
		if ( ! $this->files->write( '.htaccess', $new ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed', 'snippet' => $this->nginx_snippet() );
		}
		abody_opt_set( 'abody_edge', array( 'active' => 1, 'at' => time() ) );
		return array( 'ok' => true );
	}

	public function disable_htaccess() {
		$content  = $this->files->read( '.htaccess' );
		$stripped = $this->files->strip_block( $content, self::LABEL );
		$backup   = abody_opt_get( 'abody_edge_backup' );
		if ( is_array( $backup ) && empty( $backup['existed'] ) && '' === trim( $stripped ) ) {
			$this->files->delete( '.htaccess' );
		} else {
			$this->files->write( '.htaccess', $stripped );
		}
		abody_opt_set( 'abody_edge', array( 'active' => 0 ) );
		abody_opt_delete( 'abody_edge_backup' );
		return array( 'ok' => true );
	}

	public function is_active() {
		$s = abody_opt_get( 'abody_edge' );
		return ( is_array( $s ) && ! empty( $s['active'] ) );
	}
}
