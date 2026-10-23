<?php
/**
 * Rule-pack engine for PHP2Shell Shield.
 *
 * A rule pack is a signed JSON file describing one threat: which PHP versions
 * are fixed, which mitigations apply, and plain advice. The engine verifies a
 * detached RSA-SHA256 signature over the exact bytes of the pack file against
 * the public key bundled with the plugin, and REFUSES any pack that does not
 * verify. This is what makes auto-updating an open-source security plugin
 * safe: a poisoned or tampered pack is rejected before it is ever used.
 *
 * RSA-SHA256 via OpenSSL is used (not ed25519/sodium) because the plugin must
 * run on PHP 5.4, where libsodium is not available.
 *
 * WordPress-independent so it can be tested from the CLI.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'P2S_STANDALONE' ) ) {
	exit;
}

class P2S_Engine {

	/** @var string Directory holding the built-in packs + public key. */
	protected $builtin_dir;

	/** @var string Directory holding installed/updated packs (writable). */
	protected $installed_dir;

	/** @var string Public key PEM. */
	protected $pubkey;

	/** @var array Verified-pack cache. */
	protected $cache = array();

	/**
	 * @param string|null $builtin_dir   Defaults to the plugin's packs/ dir.
	 * @param string|null $installed_dir Optional writable dir for updates.
	 * @param string|null $pubkey_pem    Override public key (tests).
	 */
	public function __construct( $builtin_dir = null, $installed_dir = null, $pubkey_pem = null ) {
		if ( null === $builtin_dir ) {
			$builtin_dir = defined( 'P2S_DIR' ) ? P2S_DIR . 'packs/' : getcwd() . '/packs/';
		}
		$this->builtin_dir   = rtrim( $builtin_dir, '/\\' ) . '/';
		$this->installed_dir = $installed_dir ? rtrim( $installed_dir, '/\\' ) . '/' : '';
		$this->pubkey        = ( null !== $pubkey_pem ) ? $pubkey_pem : $this->load_pubkey();
	}

	protected function load_pubkey() {
		$f = $this->builtin_dir . 'signing-key.pub';
		if ( file_exists( $f ) ) {
			$c = file_get_contents( $f );
			return ( false === $c ) ? '' : $c;
		}
		return '';
	}

	/** Is signature verification possible on this host? */
	public function can_verify() {
		return function_exists( 'openssl_verify' ) && '' !== $this->pubkey;
	}

	/**
	 * Verify a detached base64 signature over $data against the public key.
	 *
	 * @param string $data   Exact pack bytes.
	 * @param string $sig_b64 Base64 signature.
	 * @return bool
	 */
	public function verify_bytes( $data, $sig_b64 ) {
		if ( ! $this->can_verify() ) {
			return false;
		}
		$sig = base64_decode( trim( (string) $sig_b64 ), true );
		if ( false === $sig || '' === $sig ) {
			return false;
		}
		// phpcs:ignore PHPCompatibility.Constants.NewConstants.openssl_algo_sha256Found -- compat.php defines a fallback value for PHP < 5.4.8.
		$res = openssl_verify( $data, $sig, $this->pubkey, OPENSSL_ALGO_SHA256 );
		return ( 1 === $res );
	}

	/**
	 * Load and verify a pack by id. Prefers an installed/updated copy, falls
	 * back to the built-in one. Returns null if nothing verifies.
	 *
	 * @param string $id Pack id, e.g. "php2shell".
	 * @return array|null
	 */
	public function load( $id ) {
		if ( ! preg_match( '/^[a-z0-9_-]+$/i', (string) $id ) ) {
			return null;
		}
		if ( isset( $this->cache[ $id ] ) ) {
			return $this->cache[ $id ];
		}

		$dirs = array();
		if ( '' !== $this->installed_dir ) {
			$dirs[] = $this->installed_dir;
		}
		$dirs[] = $this->builtin_dir;

		foreach ( $dirs as $dir ) {
			$json_f = $dir . $id . '.pack.json';
			$sig_f  = $dir . $id . '.pack.sig';
			if ( ! file_exists( $json_f ) || ! file_exists( $sig_f ) ) {
				continue;
			}
			$data = file_get_contents( $json_f );
			$sig  = file_get_contents( $sig_f );
			if ( false === $data || false === $sig ) {
				continue;
			}
			if ( ! $this->verify_bytes( $data, $sig ) ) {
				// Tampered or unsigned — skip it (do NOT trust it).
				continue;
			}
			$arr = json_decode( $data, true );
			if ( ! is_array( $arr ) ) {
				continue;
			}
			$arr['_verified'] = true;
			$arr['_source']   = ( $dir === $this->installed_dir ) ? 'installed' : 'builtin';
			$this->cache[ $id ] = $arr;
			return $arr;
		}

		return null;
	}

	/**
	 * Install an updated pack after verifying it. Writes atomically.
	 *
	 * @param string $id        Pack id.
	 * @param string $json_bytes Pack JSON bytes.
	 * @param string $sig_b64   Base64 signature.
	 * @return array ok + reason.
	 */
	public function install( $id, $json_bytes, $sig_b64 ) {
		if ( ! preg_match( '/^[a-z0-9_-]+$/i', (string) $id ) ) {
			return array( 'ok' => false, 'reason' => 'bad_id' );
		}
		if ( '' === $this->installed_dir ) {
			return array( 'ok' => false, 'reason' => 'no_install_dir' );
		}
		if ( ! $this->verify_bytes( $json_bytes, $sig_b64 ) ) {
			return array( 'ok' => false, 'reason' => 'bad_signature' );
		}
		$arr = json_decode( $json_bytes, true );
		if ( ! is_array( $arr ) || ! isset( $arr['id'] ) || $arr['id'] !== $id ) {
			return array( 'ok' => false, 'reason' => 'bad_pack' );
		}
		if ( ! is_dir( $this->installed_dir ) ) {
			@mkdir( $this->installed_dir, 0755, true );
		}
		$json_f = $this->installed_dir . $id . '.pack.json';
		$sig_f  = $this->installed_dir . $id . '.pack.sig';
		if ( false === $this->atomic_write( $json_f, $json_bytes ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed' );
		}
		if ( false === $this->atomic_write( $sig_f, trim( (string) $sig_b64 ) . "\n" ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed' );
		}
		unset( $this->cache[ $id ] );
		return array( 'ok' => true, 'pack_version' => isset( $arr['pack_version'] ) ? $arr['pack_version'] : '?' );
	}

	protected function atomic_write( $path, $content ) {
		$tmp = $path . '.tmp-' . substr( md5( uniqid( 'p2s', true ) ), 0, 8 );
		if ( false === file_put_contents( $tmp, $content, LOCK_EX ) ) {
			return false;
		}
		if ( ! @rename( $tmp, $path ) ) {
			@unlink( $tmp );
			return false;
		}
		return true;
	}

	/* ---- convenience accessors for the PHP2Shell pack ------------------ */

	/**
	 * Fixed-version map for PHP, e.g. array('8.2'=>'8.2.35', ...). Null if the
	 * pack is unavailable/unverified.
	 *
	 * @return array|null
	 */
	public function php_fixed_map() {
		$p = $this->load( 'php2shell' );
		if ( $p && isset( $p['affects']['php_fixed'] ) && is_array( $p['affects']['php_fixed'] ) ) {
			return $p['affects']['php_fixed'];
		}
		return null;
	}

	/**
	 * Mitigation ini map, e.g. array('memory_limit'=>'-1', ...). Null if N/A.
	 *
	 * @return array|null
	 */
	public function mitigation_ini() {
		$p = $this->load( 'php2shell' );
		if ( $p && isset( $p['mitigations']['ini'] ) && is_array( $p['mitigations']['ini'] ) ) {
			return $p['mitigations']['ini'];
		}
		return null;
	}

	/**
	 * A small summary of the active pack for display.
	 *
	 * @return array
	 */
	public function summary( $id = 'php2shell' ) {
		$p = $this->load( $id );
		if ( ! $p ) {
			return array(
				'loaded'     => false,
				'can_verify' => $this->can_verify(),
			);
		}
		return array(
			'loaded'       => true,
			'can_verify'   => $this->can_verify(),
			'name'         => isset( $p['name'] ) ? $p['name'] : $id,
			'pack_version' => isset( $p['pack_version'] ) ? $p['pack_version'] : '?',
			'updated'      => isset( $p['updated'] ) ? $p['updated'] : '',
			'cve'          => isset( $p['cve'] ) ? $p['cve'] : array(),
			'severity'     => isset( $p['severity'] ) ? $p['severity'] : '',
			'source'       => isset( $p['_source'] ) ? $p['_source'] : 'builtin',
		);
	}
}
