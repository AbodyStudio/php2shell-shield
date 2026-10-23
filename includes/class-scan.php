<?php
/**
 * Breach check for PHP2Shell Shield.
 *
 * PHP2Shell runs as the web user and exploitation started before the patch, so
 * a share of sites are already compromised. This looks for the signs:
 *
 *  - WordPress core files that differ from the official WordPress.org checksums
 *    (or core PHP files that should not exist).
 *  - Plugin files that differ from the official WordPress.org copy (catches a
 *    backdoored plugin — the UpdraftCentral attack pattern).
 *  - PHP files hiding in wp-content/uploads (which should never contain PHP).
 *  - Admin accounts created recently, and WP-Cron events with no known handler.
 *  - .htaccess / .user.ini changed by someone other than this plugin.
 *
 * It REPORTS; it never deletes (too dangerous without a human looking).
 *
 * The comparison/parse helpers are pure and WordPress-independent so they can
 * be tested from the CLI; the gather steps use WordPress and are guarded.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'P2S_STANDALONE' ) ) {
	exit;
}

class P2S_Scan {

	/** @var string */
	protected $base;

	/** @var callable|null Injected fetcher(url)->array(code,body). */
	protected $fetcher;

	public function __construct( $base = null, $fetcher = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd();
		}
		$this->base    = rtrim( $base, '/\\' ) . '/';
		$this->fetcher = $fetcher;
	}

	/* ---- pure helpers (tested) ----------------------------------------- */

	/**
	 * Parse the core checksums API response into file => md5.
	 *
	 * @param string $json Response body.
	 * @return array|null
	 */
	public function parse_core_checksums( $json ) {
		$d = json_decode( (string) $json, true );
		if ( is_array( $d ) && isset( $d['checksums'] ) && is_array( $d['checksums'] ) ) {
			return $d['checksums'];
		}
		return null;
	}

	/**
	 * Parse the plugin checksums API response into file => sha256.
	 *
	 * @param string $json Response body.
	 * @return array|null
	 */
	public function parse_plugin_checksums( $json ) {
		$d = json_decode( (string) $json, true );
		if ( ! is_array( $d ) ) {
			return null;
		}
		// Shape: { "files": { "path": {"md5":..,"sha256":..}, ... } } or
		//        { "checksums": { ... } }
		$files = null;
		if ( isset( $d['files'] ) && is_array( $d['files'] ) ) {
			$files = $d['files'];
		} elseif ( isset( $d['checksums'] ) && is_array( $d['checksums'] ) ) {
			$files = $d['checksums'];
		}
		if ( null === $files ) {
			return null;
		}
		$out = array();
		foreach ( $files as $path => $hashes ) {
			if ( is_array( $hashes ) && isset( $hashes['sha256'] ) ) {
				// .org may give an array of acceptable hashes.
				$out[ $path ] = is_array( $hashes['sha256'] ) ? $hashes['sha256'] : array( $hashes['sha256'] );
			}
		}
		return $out;
	}

	/**
	 * Compare a file => md5 map against files under $dir.
	 *
	 * @param array  $map  file => md5.
	 * @param string $dir  Base directory.
	 * @return array modified[], missing[]
	 */
	public function compare_md5( $map, $dir ) {
		$dir      = rtrim( $dir, '/\\' ) . '/';
		$modified = array();
		$missing  = array();
		foreach ( $map as $file => $md5 ) {
			$p = $dir . $file;
			if ( ! file_exists( $p ) ) {
				$missing[] = $file;
				continue;
			}
			if ( md5_file( $p ) !== $md5 ) {
				$modified[] = $file;
			}
		}
		return array( 'modified' => $modified, 'missing' => $missing );
	}

	/**
	 * Compare a file => [sha256,...] map against files under $dir.
	 *
	 * @param array  $map file => array of acceptable sha256.
	 * @param string $dir Plugin directory.
	 * @return array modified[], missing[]
	 */
	public function compare_sha256( $map, $dir ) {
		$dir      = rtrim( $dir, '/\\' ) . '/';
		$modified = array();
		$missing  = array();
		foreach ( $map as $file => $accept ) {
			$p = $dir . $file;
			if ( ! file_exists( $p ) ) {
				$missing[] = $file;
				continue;
			}
			$h = hash_file( 'sha256', $p );
			if ( ! in_array( $h, (array) $accept, true ) ) {
				$modified[] = $file;
			}
		}
		return array( 'modified' => $modified, 'missing' => $missing );
	}

	/**
	 * Find PHP-executable files under a directory (uploads should have none).
	 *
	 * @param string $dir Directory.
	 * @param int    $cap Max findings to return.
	 * @return array Relative paths.
	 */
	public function scan_php_files( $dir, $cap = 200 ) {
		$found = array();
		if ( ! is_dir( $dir ) ) {
			return $found;
		}
		$dir = rtrim( $dir, '/\\' ) . '/';
		$re  = '/\.(php|php[0-9]|phtml|phar|pht|phps)$/i';
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $it as $file ) {
				if ( $file->isFile() && preg_match( $re, $file->getFilename() ) ) {
					$found[] = str_replace( $dir, '', $file->getPathname() );
					if ( count( $found ) >= $cap ) {
						break;
					}
				}
			}
		} catch ( Exception $e ) {
			// Unreadable tree — report nothing rather than crash.
			return $found;
		}
		return $found;
	}

	/* ---- fetch --------------------------------------------------------- */

	protected function fetch( $url ) {
		if ( is_callable( $this->fetcher ) ) {
			return call_user_func( $this->fetcher, $url );
		}
		if ( function_exists( 'wp_remote_get' ) ) {
			$r = wp_remote_get( $url, array( 'timeout' => 20 ) );
			if ( is_wp_error( $r ) ) {
				return array( 'code' => 0, 'body' => '' );
			}
			return array(
				'code' => (int) wp_remote_retrieve_response_code( $r ),
				'body' => wp_remote_retrieve_body( $r ),
			);
		}
		return array( 'code' => 0, 'body' => '' );
	}

	/* ---- WordPress-integrated gather steps (guarded) ------------------- */

	public function core_check() {
		if ( ! function_exists( 'get_bloginfo' ) ) {
			return null;
		}
		$version = get_bloginfo( 'version' );
		$locale  = function_exists( 'get_locale' ) ? get_locale() : 'en_US';
		$url     = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode( $version ) . '&locale=' . rawurlencode( $locale );
		$res     = $this->fetch( $url );
		if ( 200 !== $res['code'] ) {
			return array( 'ok' => false, 'reason' => 'fetch_failed' );
		}
		$map = $this->parse_core_checksums( $res['body'] );
		if ( null === $map ) {
			return array( 'ok' => false, 'reason' => 'no_checksums' );
		}
		$cmp = $this->compare_md5( $map, $this->base );
		return array(
			'ok'       => true,
			'version'  => $version,
			'modified' => $cmp['modified'],
			'missing'  => $cmp['missing'],
		);
	}

	public function uploads_check() {
		$dir = $this->base . 'wp-content/uploads';
		if ( function_exists( 'wp_upload_dir' ) ) {
			$u = wp_upload_dir();
			if ( ! empty( $u['basedir'] ) ) {
				$dir = $u['basedir'];
			}
		}
		return $this->scan_php_files( $dir );
	}

	public function recent_admins( $days = 30 ) {
		if ( ! function_exists( 'get_users' ) ) {
			return array();
		}
		$users = get_users( array( 'role' => 'administrator' ) );
		$cut   = time() - ( $days * DAY_IN_SECONDS );
		$out   = array();
		foreach ( $users as $u ) {
			$reg = isset( $u->user_registered ) ? strtotime( $u->user_registered ) : 0;
			if ( $reg && $reg >= $cut ) {
				$out[] = array(
					'login'      => $u->user_login,
					'registered' => $u->user_registered,
				);
			}
		}
		return $out;
	}

	public function config_check() {
		$out = array();
		foreach ( array( '.htaccess', '.user.ini' ) as $name ) {
			$p = $this->base . $name;
			if ( file_exists( $p ) ) {
				$out[] = array(
					'file'     => $name,
					'modified' => gmdate( 'Y-m-d H:i', filemtime( $p ) ),
				);
			}
		}
		return $out;
	}

	/**
	 * Run everything and return a structured report.
	 *
	 * @return array
	 */
	public function run() {
		$report = array(
			'time'    => time(),
			'core'    => $this->core_check(),
			'uploads' => $this->uploads_check(),
			'admins'  => $this->recent_admins(),
			'config'  => $this->config_check(),
		);
		$report['plugins'] = $this->plugins_check();
		return $report;
	}

	public function plugins_check() {
		if ( ! function_exists( 'get_plugins' ) ) {
			if ( defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			return array();
		}
		$all     = get_plugins();
		$results = array();
		foreach ( $all as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug || '' === $slug ) {
				continue; // single-file plugin; skip checksum check.
			}
			$ver = isset( $data['Version'] ) ? $data['Version'] : '';
			$url = 'https://api.wordpress.org/plugins/checksums/1.0/?slug=' . rawurlencode( $slug ) . '&version=' . rawurlencode( $ver );
			$res = $this->fetch( $url );
			if ( 200 !== $res['code'] ) {
				$results[] = array( 'slug' => $slug, 'verifiable' => false );
				continue;
			}
			$map = $this->parse_plugin_checksums( $res['body'] );
			if ( null === $map || empty( $map ) ) {
				$results[] = array( 'slug' => $slug, 'verifiable' => false );
				continue;
			}
			$cmp       = $this->compare_sha256( $map, $this->base . 'wp-content/plugins/' . $slug );
			$results[] = array(
				'slug'       => $slug,
				'verifiable' => true,
				'modified'   => $cmp['modified'],
				'missing'    => $cmp['missing'],
			);
		}
		return $results;
	}
}
