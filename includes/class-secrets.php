<?php
/**
 * Secrets reset for PHP2Shell Shield.
 *
 * PHP2Shell can leak memory that held passwords, API keys, and session data.
 * This rotates WordPress's eight auth keys/salts in wp-config.php, which
 * invalidates every existing login cookie (so a stolen session is useless) and
 * forces a fresh login for everyone.
 *
 * wp-config.php is the most dangerous file to edit — a broken one takes the
 * whole site down — so this:
 *   - generates quote-safe salts (no ' " \ $ ` so they can never break the PHP),
 *   - replaces each define() line by line (never touching the value's content),
 *   - validates the result before writing (opener intact, define count stable),
 *   - writes atomically (temp + rename), and
 *   - keeps a protected backup of the original first.
 *
 * The rotate() transform is pure and testable; file handling uses WordPress-ish
 * paths but no WordPress functions, so it can be exercised from the CLI too.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Secrets {

	/** The eight constants WordPress uses for auth keys and salts. */
	public function keys() {
		return array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);
	}

	/** @var string */
	protected $base;

	public function __construct( $base = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd() . '/';
		}
		$this->base = rtrim( $base, '/\\' ) . '/';
	}

	/* ---- pure transform (tested) --------------------------------------- */

	/**
	 * Replace each auth key/salt define() with a fresh value.
	 *
	 * @param string   $content  wp-config.php content.
	 * @param array|null $newvals Optional map KEY=>value (tests); else random.
	 * @return array content, rotated[], missing[], ok (bool).
	 */
	public function rotate( $content, $newvals = null ) {
		$rotated = array();
		$missing = array();
		$before  = substr_count( $content, 'define' );

		foreach ( $this->keys() as $key ) {
			$value = ( is_array( $newvals ) && isset( $newvals[ $key ] ) ) ? $newvals[ $key ] : p2s_random_string( 64 );
			// Match the whole single line that defines this key.
			$pattern = '/^[^\r\n]*\bdefine\s*\(\s*([\'"])' . $key . '\1.*$/m';
			if ( ! preg_match( $pattern, $content ) ) {
				$missing[] = $key;
				continue;
			}
			$replacement = "define('" . $key . "', '" . $value . "');";
			// Callback keeps the replacement literal (no backref surprises).
			$content = preg_replace_callback(
				$pattern,
				create_p2s_literal( $replacement ),
				$content,
				1
			);
			$rotated[] = $key;
		}

		$after = substr_count( $content, 'define' );
		$ok    = ( 0 === strpos( ltrim( $content ), '<?php' ) ) && ( $after === $before ) && ! empty( $rotated );

		return array(
			'content' => $content,
			'rotated' => $rotated,
			'missing' => $missing,
			'ok'      => $ok,
		);
	}

	/* ---- file handling ------------------------------------------------- */

	/**
	 * Locate wp-config.php (site root, or one level up as WordPress allows).
	 *
	 * @return string|false
	 */
	public function locate() {
		$a = $this->base . 'wp-config.php';
		if ( file_exists( $a ) ) {
			return $a;
		}
		// WordPress also looks one level up, but only if that dir is not itself
		// another WordPress install.
		$up = dirname( rtrim( $this->base, '/\\' ) ) . '/wp-config.php';
		if ( file_exists( $up ) && ! file_exists( dirname( rtrim( $this->base, '/\\' ) ) . '/wp-settings.php' ) ) {
			return $up;
		}
		return false;
	}

	protected function backup_dir() {
		if ( function_exists( 'wp_upload_dir' ) ) {
			$u = wp_upload_dir();
			if ( ! empty( $u['basedir'] ) ) {
				return rtrim( $u['basedir'], '/\\' ) . '/php2shell-shield/backups/';
			}
		}
		return $this->base . 'wp-content/uploads/php2shell-shield/backups/';
	}

	protected function harden_backup_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			@mkdir( $dir, 0755, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
		}
		// Deny web access to the backup (it holds the original secrets).
		@file_put_contents( $dir . '.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
		@file_put_contents( $dir . 'index.php', "<?php\n// Silence is golden.\n" );
	}

	/**
	 * Rotate the salts in the real wp-config.php.
	 *
	 * @return array
	 */
	public function rotate_file() {
		$path = $this->locate();
		if ( false === $path ) {
			return array( 'ok' => false, 'reason' => 'no_wpconfig' );
		}
		if ( ! is_writable( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
			return array( 'ok' => false, 'reason' => 'not_writable' );
		}
		$content = file_get_contents( $path );
		if ( false === $content ) {
			return array( 'ok' => false, 'reason' => 'read_failed' );
		}

		$res = $this->rotate( $content );
		if ( empty( $res['ok'] ) ) {
			return array( 'ok' => false, 'reason' => 'transform_failed', 'missing' => $res['missing'] );
		}

		// Back up the original (protected) before touching the live file.
		$bdir = $this->backup_dir();
		$this->harden_backup_dir( $bdir );
		$bfile = $bdir . 'wp-config-' . gmdate( 'Ymd-His' ) . '.bak';
		if ( false !== @file_put_contents( $bfile, $content ) ) {
			@chmod( $bfile, 0600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
		} else {
			$bfile = '';
		}

		// Atomic write.
		$tmp = $path . '.p2s-tmp-' . substr( md5( uniqid( 'p2s', true ) ), 0, 8 );
		if ( false === @file_put_contents( $tmp, $res['content'], LOCK_EX ) ) {
			return array( 'ok' => false, 'reason' => 'write_failed' );
		}
		@chmod( $tmp, @fileperms( $path ) & 0777 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
			@unlink( $tmp );
			return array( 'ok' => false, 'reason' => 'rename_failed' );
		}

		return array(
			'ok'      => true,
			'rotated' => $res['rotated'],
			'missing' => $res['missing'],
			'backup'  => $bfile,
		);
	}

	/**
	 * The manual checklist of secrets the plugin cannot rotate itself.
	 *
	 * @return array
	 */
	public function checklist() {
		return array(
			'Database password (in wp-config.php, and at your host)',
			'Hosting / cPanel / SFTP password',
			'SMTP or email-sending password',
			'Payment and other API keys (Stripe, PayPal, etc.)',
			'Any API keys stored in plugin settings',
			'Admin user passwords (ask users to reset)',
		);
	}
}

if ( ! function_exists( 'create_p2s_literal' ) ) {
	/**
	 * Return a callback that outputs a fixed literal, for preg_replace_callback.
	 * (A small closure factory so PHP 5.4 keeps a single code path.)
	 *
	 * @param string $literal The exact replacement text.
	 * @return callable
	 */
	function create_p2s_literal( $literal ) {
		return function ( $m ) use ( $literal ) {
			return $literal;
		};
	}
}
