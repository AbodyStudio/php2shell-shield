<?php
/**
 * cPanel PHP-version switcher for PHP2Shell Shield.
 *
 * On most cPanel (EA4) sites the active PHP version is written into .htaccess as
 * a handler line (application/x-httpd-ea-phpNN). Where that is the case, this
 * can switch it to another installed version in one click — with a safety net:
 *
 *   1. back up .htaccess,
 *   2. rewrite the handler to the new version,
 *   3. make loopback requests to confirm the site still returns 200 AND is now
 *      running the target PHP,
 *   4. if that cannot be confirmed, REVERT .htaccess from the backup.
 *
 * The admin request that triggers the switch keeps running on the OLD PHP (a
 * handler change only affects the NEXT request), so it can always perform the
 * revert even if the new version breaks the site.
 *
 * Changing PHP is fundamentally a hosting-panel action; this works only where
 * the version lives in .htaccess. Elsewhere the admin UI links to cPanel's
 * MultiPHP Manager instead.
 *
 * Parsing/rewrite helpers are pure and testable; the live switch uses WordPress.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_PhpSwitch {

	/** @var string */
	protected $base;

	/** @var array|null Injected available versions (tests). */
	protected $available_override;

	public function __construct( $base = null, $available_override = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd() . '/';
		}
		$this->base               = rtrim( $base, '/\\' ) . '/';
		$this->available_override = $available_override;

		// Lightweight probe endpoint for post-switch verification.
		if ( function_exists( 'add_action' ) ) {
			add_action( 'init', array( $this, 'maybe_probe' ), 0 );
		}
	}

	/* ---- pure parsing / rewrite (tested) ------------------------------- */

	/** The PHP version in a cPanel EA4 handler line, or '' if none. */
	public function handler_version( $htaccess ) {
		if ( preg_match( '/application\/x-httpd-ea-php(\d)(\d)/', (string) $htaccess, $m ) ) {
			return $m[1] . '.' . $m[2];
		}
		return '';
	}

	/** Rewrite every EA4 handler to $version (e.g. "8.3"); returns new content. */
	public function set_handler_version( $htaccess, $version ) {
		$vv = str_replace( '.', '', $version );
		if ( ! preg_match( '/^\d\d$/', $vv ) ) {
			return $htaccess;
		}
		$out = preg_replace( '/application\/x-httpd-ea-php\d\d/', 'application/x-httpd-ea-php' . $vv, (string) $htaccess );
		return ( null === $out ) ? $htaccess : $out;
	}

	/** cPanel EA4 PHP versions installed on the server (e.g. ["7.4","8.2"]). */
	public function available_versions() {
		if ( null !== $this->available_override ) {
			return $this->available_override;
		}
		$out = array();
		$dirs = @glob( '/opt/cpanel/ea-php*', GLOB_ONLYDIR );
		if ( is_array( $dirs ) ) {
			foreach ( $dirs as $d ) {
				if ( preg_match( '/ea-php(\d)(\d)$/', $d, $m ) ) {
					$out[] = $m[1] . '.' . $m[2];
				}
			}
		}
		sort( $out );
		return $out;
	}

	public function is_cpanel() {
		return ( is_dir( '/usr/local/cpanel' ) || is_dir( '/opt/cpanel' ) );
	}

	/**
	 * Detect what's possible here.
	 *
	 * @return array
	 */
	public function detect() {
		$htaccess = '';
		$path     = $this->base . '.htaccess';
		if ( file_exists( $path ) ) {
			$c = file_get_contents( $path );
			$htaccess = ( false === $c ) ? '' : $c;
		}
		$current = $this->handler_version( $htaccess );
		return array(
			'cpanel'    => $this->is_cpanel(),
			'current'   => $current,
			'available' => $this->available_versions(),
			'method'    => ( '' !== $current ) ? 'htaccess' : 'none',
			'writable'  => ( file_exists( $path ) ? is_writable( $path ) : is_writable( $this->base ) ), // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
		);
	}

	/* ---- the switch ---------------------------------------------------- */

	/**
	 * Switch PHP to $version with backup + verification + auto-revert.
	 *
	 * @param string $version major.minor, e.g. "8.2".
	 * @return array ok + reason/detail.
	 */
	public function switch_to( $version ) {
		$d = $this->detect();
		if ( 'htaccess' !== $d['method'] ) {
			return array( 'ok' => false, 'reason' => 'no_handler' );
		}
		if ( ! empty( $d['available'] ) && ! in_array( $version, $d['available'], true ) ) {
			return array( 'ok' => false, 'reason' => 'not_installed' );
		}
		$path = $this->base . '.htaccess';
		if ( ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
			return array( 'ok' => false, 'reason' => 'not_writable' );
		}
		$orig = file_get_contents( $path );
		if ( false === $orig ) {
			return array( 'ok' => false, 'reason' => 'read_failed' );
		}
		$new = $this->set_handler_version( $orig, $version );
		if ( $new === $orig ) {
			return array( 'ok' => false, 'reason' => 'no_handler' );
		}

		p2s_opt_set( 'p2s_phpswitch_backup', array( 'content' => $orig, 'from' => $d['current'], 'at' => time() ) );

		if ( ! $this->write( $path, $new ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed' );
		}

		// Verify on the NEW handler; revert if it does not come up cleanly.
		$check = $this->verify( $version );
		if ( empty( $check['ok'] ) ) {
			$this->write( $path, $orig ); // auto-revert
			return array(
				'ok'     => false,
				'reason' => 'reverted',
				'detail' => isset( $check['detail'] ) ? $check['detail'] : 'site did not come up on PHP ' . $version,
			);
		}

		return array( 'ok' => true, 'from' => $d['current'], 'to' => $version );
	}

	/** Make loopback requests to confirm the site runs on $version. */
	protected function verify( $version ) {
		if ( ! function_exists( 'home_url' ) || ! function_exists( 'wp_remote_get' ) ) {
			return array( 'ok' => false, 'detail' => 'verification unavailable' );
		}
		$token = substr( md5( uniqid( 'p2s', true ) ), 0, 16 );
		set_transient( 'p2s_phpprobe', $token, 120 );

		// 1) Probe request: our init hook echoes the running PHP version + token.
		$probe = wp_remote_get(
			add_query_arg( 'p2s_probe', $token, home_url( '/' ) ),
			array( 'timeout' => 15, 'sslverify' => false, 'redirection' => 1 )
		);
		$ok_probe = false;
		if ( ! is_wp_error( $probe ) && 200 === (int) wp_remote_retrieve_response_code( $probe ) ) {
			$body = wp_remote_retrieve_body( $probe );
			if ( false !== strpos( $body, 'P2S_PHP:' . $version . '.' ) && false !== strpos( $body, $token ) ) {
				$ok_probe = true;
			}
		}

		// 2) Plain request: confirm the front page boots (no fatal) on new PHP.
		$home    = wp_remote_get( home_url( '/' ), array( 'timeout' => 15, 'sslverify' => false, 'redirection' => 1 ) );
		$ok_home = ( ! is_wp_error( $home ) && (int) wp_remote_retrieve_response_code( $home ) < 500 );

		delete_transient( 'p2s_phpprobe' );

		if ( $ok_probe && $ok_home ) {
			return array( 'ok' => true );
		}
		if ( ! $ok_probe ) {
			return array( 'ok' => false, 'detail' => 'the server did not confirm PHP ' . $version . ' (the handler may be invalid or that version is not installed)' );
		}
		return array( 'ok' => false, 'detail' => 'the site returned a server error on PHP ' . $version );
	}

	/** Early probe responder: prints the running PHP version when the token matches. */
	public function maybe_probe() {
		if ( empty( $_GET['p2s_probe'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$token = get_transient( 'p2s_phpprobe' );
		$given = sanitize_text_field( wp_unslash( $_GET['p2s_probe'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $token && p2s_hash_equals( (string) $token, $given ) ) {
			header( 'Content-Type: text/plain' );
			echo 'P2S_PHP:' . PHP_VERSION . ':' . $given; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- constant + validated token.
			exit;
		}
	}

	/** Best-effort MultiPHP Manager hint for non-htaccess hosts. */
	public function multiphp_hint() {
		$host = '';
		if ( function_exists( 'home_url' ) ) {
			$host = (string) parse_url( home_url(), PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		}
		return array(
			'url'  => $host ? 'https://' . $host . ':2083/' : '',
			'text' => 'Open cPanel, go to MultiPHP Manager, select your domain, and choose the new PHP version.',
		);
	}

	protected function write( $path, $content ) {
		$tmp = $path . '.p2s-tmp-' . substr( md5( uniqid( 'p2s', true ) ), 0, 8 );
		if ( false === @file_put_contents( $tmp, $content, LOCK_EX ) ) {
			return false;
		}
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
			@unlink( $tmp );
			return false;
		}
		return true;
	}
}
