<?php
/**
 * GitHub auto-updater for PHP2Shell Shield — with signed-download verification.
 *
 * Hooks into WordPress's own plugin-update system so updates appear and install
 * like any other plugin, but pulls from this plugin's GitHub Releases instead of
 * WordPress.org. Because this is a security plugin, it does NOT trust the
 * download blindly: before WordPress installs the zip, the updater verifies a
 * detached RSA-SHA256 signature of the exact zip bytes against the public key
 * bundled with the plugin (the same key that signs rule packs). An unsigned or
 * tampered download is refused — the update is blocked rather than installed.
 *
 * Each release must attach two assets: the plugin zip and a matching
 * "<zip>.sig" (base64 signature). build.sh produces both when the private key
 * is present.
 *
 * Stays PHP 5.4 compatible.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Updater {

	/** @var string owner/repo */
	protected $repo = 'AbodyStudio/php2shell-shield';

	/** @var string e.g. php2shell-shield/php2shell-shield.php */
	protected $basename;

	/** @var string e.g. php2shell-shield */
	protected $slug;

	public function __construct() {
		$this->basename = defined( 'P2S_FILE' ) && function_exists( 'plugin_basename' ) ? plugin_basename( P2S_FILE ) : 'php2shell-shield/php2shell-shield.php';
		$this->slug     = dirname( $this->basename );

		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check' ) );
		add_filter( 'plugins_api', array( $this, 'info' ), 20, 3 );
		add_filter( 'upgrader_pre_download', array( $this, 'verify_download' ), 10, 4 );
	}

	/* ---- release lookup (cached) --------------------------------------- */

	/**
	 * Parse the GitHub "latest release" API response into the bits we need.
	 * Pure (testable): no WordPress calls.
	 *
	 * @param string $json Response body.
	 * @return array
	 */
	public function parse_release( $json ) {
		$d = json_decode( (string) $json, true );
		if ( ! is_array( $d ) ) {
			return array( 'ok' => false );
		}
		$ver = isset( $d['tag_name'] ) ? ltrim( (string) $d['tag_name'], 'vV' ) : '';
		$zip = '';
		$sig = '';
		if ( ! empty( $d['assets'] ) && is_array( $d['assets'] ) ) {
			foreach ( $d['assets'] as $a ) {
				$name = isset( $a['name'] ) ? (string) $a['name'] : '';
				$url  = isset( $a['browser_download_url'] ) ? (string) $a['browser_download_url'] : '';
				if ( '.sig' === substr( $name, -4 ) ) {
					$sig = $url;
				} elseif ( '.zip' === substr( $name, -4 ) ) {
					$zip = $url;
				}
			}
		}
		return array(
			'ok'        => ( '' !== $ver && '' !== $zip ),
			'version'   => $ver,
			'zip'       => $zip,
			'sig'       => $sig,
			'body'      => isset( $d['body'] ) ? (string) $d['body'] : '',
			'html_url'  => isset( $d['html_url'] ) ? (string) $d['html_url'] : ( 'https://github.com/' . $this->repo ),
			'published' => isset( $d['published_at'] ) ? (string) $d['published_at'] : '',
		);
	}

	protected function latest() {
		$cached = get_site_transient( 'p2s_gh_release' );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$resp = wp_remote_get(
			'https://api.github.com/repos/' . $this->repo . '/releases/latest',
			array(
				'timeout' => 15,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'PHP2Shell-Shield',
				),
			)
		);
		if ( is_wp_error( $resp ) || 200 !== (int) wp_remote_retrieve_response_code( $resp ) ) {
			$fail = array( 'ok' => false );
			set_site_transient( 'p2s_gh_release', $fail, 2 * HOUR_IN_SECONDS );
			return $fail;
		}
		$out = $this->parse_release( wp_remote_retrieve_body( $resp ) );
		set_site_transient( 'p2s_gh_release', $out, 12 * HOUR_IN_SECONDS );
		return $out;
	}

	/* ---- inject update into WordPress ---------------------------------- */

	public function check( $transient ) {
		if ( ! is_object( $transient ) ) {
			$transient = new stdClass();
		}
		$r = $this->latest();
		if ( empty( $r['ok'] ) ) {
			return $transient;
		}

		if ( version_compare( $r['version'], P2S_VERSION, '>' ) ) {
			$obj = array(
				'slug'        => $this->slug,
				'plugin'      => $this->basename,
				'new_version' => $r['version'],
				'url'         => $r['html_url'],
				'package'     => $r['zip'],
			);
			if ( empty( $transient->response ) || ! is_array( $transient->response ) ) {
				$transient->response = array();
			}
			$transient->response[ $this->basename ] = (object) $obj;
		} else {
			$obj = array(
				'slug'        => $this->slug,
				'plugin'      => $this->basename,
				'new_version' => P2S_VERSION,
				'url'         => 'https://github.com/' . $this->repo,
				'package'     => '',
			);
			if ( empty( $transient->no_update ) || ! is_array( $transient->no_update ) ) {
				$transient->no_update = array();
			}
			$transient->no_update[ $this->basename ] = (object) $obj;
		}
		return $transient;
	}

	/* ---- "View details" popup ------------------------------------------ */

	public function info( $res, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $res;
		}
		if ( ! isset( $args->slug ) || $args->slug !== $this->slug ) {
			return $res;
		}
		$r         = $this->latest();
		$version   = ! empty( $r['ok'] ) ? $r['version'] : P2S_VERSION;
		$changelog = ( ! empty( $r['body'] ) ) ? wpautop( wp_kses_post( $r['body'] ) ) : 'See the GitHub releases page.';

		return (object) array(
			'name'          => 'PHP2Shell Shield',
			'slug'          => $this->slug,
			'version'       => $version,
			'author'        => '<a href="https://abodystudio.com">AbodyStudio</a>',
			'homepage'      => 'https://github.com/' . $this->repo,
			'download_link' => ! empty( $r['ok'] ) ? $r['zip'] : '',
			'sections'      => array(
				'description' => 'Risk reduction for the PHP2Shell exploit (CVE-2026-109618 / CVE-2026-109619) on sites that cannot update PHP yet. A shield, not a cure.',
				'changelog'   => $changelog,
			),
		);
	}

	/* ---- verified download (the security-critical part) ---------------- */

	/**
	 * Intercept WordPress's download of OUR package: download it, verify its
	 * signature against the bundled public key, and only then let WordPress
	 * install it. Anything unsigned or tampered is refused.
	 *
	 * @param mixed  $reply      Short-circuit value (false = let WP download).
	 * @param string $package    The package URL WordPress is about to download.
	 * @param object $upgrader   The WP_Upgrader instance.
	 * @param array  $hook_extra Context.
	 * @return mixed false (not ours), a local file path (verified), or WP_Error.
	 */
	public function verify_download( $reply, $package, $upgrader = null, $hook_extra = array() ) {
		$r = $this->latest();
		if ( empty( $r['ok'] ) || $package !== $r['zip'] ) {
			return $reply; // Not our update — leave it alone.
		}

		if ( '' === $r['sig'] ) {
			return new WP_Error( 'p2s_no_sig', 'PHP2Shell Shield: this update has no signature, so it was not installed. Download it manually from GitHub if you trust it.' );
		}

		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		$tmp = download_url( $package, 300 );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}

		$sig_resp = wp_remote_get( $r['sig'], array( 'timeout' => 30 ) );
		if ( is_wp_error( $sig_resp ) || 200 !== (int) wp_remote_retrieve_response_code( $sig_resp ) ) {
			$this->rm( $tmp );
			return new WP_Error( 'p2s_sig_fetch', 'PHP2Shell Shield: could not fetch the update signature, so the update was not installed.' );
		}
		$sig_b64 = wp_remote_retrieve_body( $sig_resp );

		$bytes = file_get_contents( $tmp );
		if ( false === $bytes || ! $this->verify_bytes( $bytes, $sig_b64 ) ) {
			$this->rm( $tmp );
			return new WP_Error( 'p2s_bad_sig', 'PHP2Shell Shield: the update signature did not match. The download may be tampered with, so installation was blocked.' );
		}

		return $tmp; // Verified — WordPress installs this file.
	}

	/** Verify a base64 signature over $data using the plugin's public key. */
	protected function verify_bytes( $data, $sig_b64 ) {
		if ( function_exists( 'p2s_engine' ) ) {
			return p2s_engine()->verify_bytes( $data, $sig_b64 );
		}
		if ( ! function_exists( 'openssl_verify' ) ) {
			return false;
		}
		$pub = @file_get_contents( P2S_DIR . 'packs/signing-key.pub' );
		if ( ! $pub ) {
			return false;
		}
		$sig = base64_decode( trim( (string) $sig_b64 ), true );
		if ( false === $sig || '' === $sig ) {
			return false;
		}
		// phpcs:ignore PHPCompatibility.Constants.NewConstants.openssl_algo_sha256Found -- compat.php defines a fallback value for PHP < 5.4.8.
		return 1 === openssl_verify( $data, $sig, $pub, OPENSSL_ALGO_SHA256 );
	}

	protected function rm( $path ) {
		if ( $path && file_exists( $path ) ) {
			@unlink( $path );
		}
	}
}
