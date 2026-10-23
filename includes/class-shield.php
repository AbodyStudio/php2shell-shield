<?php
/**
 * The shield: writes, verifies, and removes the PHP2Shell stopgap settings.
 *
 *   memory_limit                     = -1   (CVE-2026-109618)
 *   session.upload_progress.enabled  = off  (CVE-2026-109619)
 *
 * Both are PHP's own recommended interim settings. They are set in .user.ini
 * (PHP-FPM / CGI / LiteSpeed) or .htaccess (classic mod_php). Everything is
 * reversible, backed up, and verified on a later request.
 *
 * WordPress-independent so it can be tested from the CLI.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Shield {

	/** @var P2S_Files */
	protected $files;

	/** @var array Detection report. */
	protected $report;

	/** @var string Base directory. */
	protected $base;

	/** Test override for live ini values: array('memory_limit'=>..,'upload_progress'=>..) @var array|null */
	protected $live_override = null;

	/** Mitigation ini map from the rule pack (key => value). @var array|null */
	protected $ini_map = null;

	/**
	 * @param string|null $base    Base dir (defaults to ABSPATH).
	 * @param array|null  $report  Detection report (defaults to a fresh run).
	 * @param array|null  $ini_map Mitigation settings from the rule pack. Falls
	 *                             back to the built-in two if not supplied.
	 */
	public function __construct( $base = null, $report = null, $ini_map = null ) {
		if ( null === $base ) {
			$base = defined( 'ABSPATH' ) ? ABSPATH : getcwd();
		}
		$this->base   = $base;
		$this->files  = new P2S_Files( $base );
		$this->report = ( null === $report ) ? $this->fresh_report() : $report;
		if ( is_array( $ini_map ) && ! empty( $ini_map ) ) {
			$this->ini_map = $ini_map;
		}
	}

	/** The ini settings to apply (from the pack, or the built-in fallback). */
	protected function ini_pairs() {
		if ( is_array( $this->ini_map ) && ! empty( $this->ini_map ) ) {
			return $this->ini_map;
		}
		return array(
			'memory_limit'                    => '-1',
			'session.upload_progress.enabled' => '0',
		);
	}

	/** Is this value an on/off flag (vs. a scalar value)? */
	protected function is_flag_value( $v ) {
		$s = strtolower( trim( (string) $v ) );
		return in_array( $s, array( '0', '1', 'on', 'off', 'true', 'false', 'yes', 'no' ), true );
	}

	/** Normalise a flag value to on|off. */
	protected function flag_word( $v ) {
		$s = strtolower( trim( (string) $v ) );
		return in_array( $s, array( '1', 'on', 'true', 'yes' ), true ) ? 'on' : 'off';
	}

	protected function fresh_report() {
		$d = new P2S_Detect();
		return $d->run();
	}

	/** Allow tests to pretend PHP has (not) picked up the settings. */
	public function set_live_override( $memory_limit, $upload_progress ) {
		$this->live_override = array(
			'memory_limit'    => $memory_limit,
			'upload_progress' => $upload_progress,
		);
	}

	/* ---- directive text ------------------------------------------------ */

	protected function target_file( $method ) {
		return ( 'htaccess' === $method ) ? '.htaccess' : '.user.ini';
	}

	protected function lines( $method ) {
		$pairs = $this->ini_pairs();

		if ( 'htaccess' === $method ) {
			$inner = array();
			foreach ( $pairs as $k => $v ) {
				if ( $this->is_flag_value( $v ) ) {
					$inner[] = 'php_flag ' . $k . ' ' . $this->flag_word( $v );
				} else {
					$inner[] = 'php_value ' . $k . ' ' . $v;
				}
			}
			$out = array();
			// Guard every mod_php token so a server without mod_php never 500s.
			$tokens = array( 'mod_php.c', 'mod_php8.c', 'mod_php7.c', 'mod_php5.c' );
			foreach ( $tokens as $t ) {
				$out[] = '<IfModule ' . $t . '>';
				foreach ( $inner as $line ) {
					$out[] = $line;
				}
				$out[] = '</IfModule>';
			}
			return $out;
		}

		// .user.ini (ini syntax).
		$out = array();
		foreach ( $pairs as $k => $v ) {
			$out[] = $k . ' = ' . $v;
		}
		return $out;
	}

	/**
	 * A copy-paste snippet for the host / advanced users, for any method.
	 *
	 * @param string $method user_ini|htaccess|snippet
	 * @return string
	 */
	public function snippet( $method = null ) {
		if ( null === $method ) {
			$method = $this->report['shield']['method'];
		}
		if ( 'htaccess' === $method ) {
			return "# Put at the top of your site's .htaccess:\n"
				. implode( "\n", $this->lines( 'htaccess' ) );
		}
		if ( 'user_ini' === $method ) {
			return "; Put in a .user.ini file in your site root:\n"
				. implode( "\n", $this->lines( 'user_ini' ) );
		}
		// snippet-only (exotic SAPI): give the PHP-FPM pool form.
		$pool = array();
		foreach ( $this->ini_pairs() as $k => $v ) {
			if ( $this->is_flag_value( $v ) ) {
				$pool[] = 'php_admin_flag[' . $k . '] = ' . $this->flag_word( $v );
			} else {
				$pool[] = 'php_admin_value[' . $k . '] = ' . $v;
			}
		}
		return "; Add to your PHP-FPM pool config (e.g. www.conf), then restart PHP-FPM:\n"
			. implode( "\n", $pool );
	}

	/* ---- actions ------------------------------------------------------- */

	/**
	 * Turn the shield on.
	 *
	 * @return array ok, and on failure a reason + snippet.
	 */
	public function enable() {
		$method = $this->report['shield']['method'];

		if ( 'snippet' === $method ) {
			return array(
				'ok'      => false,
				'reason'  => 'snippet_only',
				'snippet' => $this->snippet( 'snippet' ),
			);
		}

		$file = $this->target_file( $method );

		if ( ! $this->files->writable( $file ) ) {
			return array(
				'ok'      => false,
				'reason'  => 'not_writable',
				'file'    => $file,
				'snippet' => $this->snippet( $method ),
			);
		}

		$original = $this->files->read( $file );
		$existed  = $this->files->exists( $file );

		// Back up the original content once (in the DB, not a stray file).
		if ( null === $this->opt_get( 'p2s_backup' ) ) {
			$this->opt_set(
				'p2s_backup',
				array(
					'file'    => $file,
					'existed' => $existed ? 1 : 0,
					'content' => $original,
				)
			);
		}

		$new = $this->files->set_block( $original, $this->lines( $method ), $file );

		if ( ! $this->files->write( $file, $new ) ) {
			return array(
				'ok'      => false,
				'reason'  => 'write_failed',
				'file'    => $file,
				'snippet' => $this->snippet( $method ),
			);
		}

		$this->opt_set(
			'p2s_shield',
			array(
				'active'     => 1,
				'method'     => $method,
				'file'       => $file,
				'written_at' => time(),
				'ttl'        => (int) $this->report['shield']['user_ini_ttl'],
			)
		);

		return array( 'ok' => true, 'method' => $method, 'file' => $file );
	}

	/**
	 * Turn the shield off and restore the file.
	 *
	 * @return array
	 */
	public function disable() {
		$state = $this->opt_get( 'p2s_shield' );
		if ( ! is_array( $state ) || empty( $state['active'] ) ) {
			return array( 'ok' => true, 'noop' => true );
		}

		$file   = $state['file'];
		$backup = $this->opt_get( 'p2s_backup' );

		$current  = $this->files->read( $file );
		$stripped = $this->files->strip_block( $current );

		$created_by_us = ( is_array( $backup ) && empty( $backup['existed'] ) );

		if ( $created_by_us && '' === trim( $stripped ) ) {
			// We created the file and nothing else is in it — remove it.
			$this->files->delete( $file );
		} else {
			$this->files->write( $file, $stripped );
		}

		$this->opt_set( 'p2s_shield', array( 'active' => 0 ) );
		$this->opt_delete( 'p2s_backup' );

		return array( 'ok' => true );
	}

	/* ---- verification -------------------------------------------------- */

	protected function live_values() {
		if ( null !== $this->live_override ) {
			return $this->live_override;
		}
		return array(
			'memory_limit'    => ini_get( 'memory_limit' ),
			'upload_progress' => ini_get( 'session.upload_progress.enabled' ),
		);
	}

	/**
	 * Verify whether the settings are actually live right now.
	 *
	 * @return array active, live_ok, phase (live|pending|stuck), remaining secs.
	 */
	public function verify() {
		$live  = $this->live_values();
		$pairs = $this->ini_pairs();

		$mem_target = isset( $pairs['memory_limit'] ) ? $pairs['memory_limit'] : '-1';
		$up_target  = isset( $pairs['session.upload_progress.enabled'] ) ? $pairs['session.upload_progress.enabled'] : '0';

		$mem_ok = ( trim( (string) $live['memory_limit'] ) === trim( (string) $mem_target ) );
		$up_ok  = ( p2s_ini_truthy( $live['upload_progress'] ) === p2s_ini_truthy( $up_target ) );
		$all_ok = ( $mem_ok && $up_ok );

		$state = $this->opt_get( 'p2s_shield' );
		if ( ! is_array( $state ) || empty( $state['active'] ) ) {
			return array(
				'active'  => false,
				'live_ok' => $all_ok,
				'phase'   => $all_ok ? 'live' : 'off',
			);
		}

		$elapsed   = time() - (int) $state['written_at'];
		$is_ini    = ( 'user_ini' === $state['method'] );
		$ttl       = $is_ini ? max( 1, (int) $state['ttl'] ) : 0;
		$remaining = 0;

		if ( $all_ok ) {
			$phase = 'live';
		} elseif ( $is_ini && $elapsed < $ttl ) {
			$phase     = 'pending';
			$remaining = $ttl - $elapsed;
		} else {
			$phase = 'stuck';
		}

		return array(
			'active'    => true,
			'live_ok'   => $all_ok,
			'phase'     => $phase,
			'remaining' => $remaining,
			'method'    => $state['method'],
			'file'      => $state['file'],
		);
	}

	public function is_active() {
		$state = $this->opt_get( 'p2s_shield' );
		return ( is_array( $state ) && ! empty( $state['active'] ) );
	}

	/** The write method for this environment: user_ini|htaccess|snippet. */
	public function method() {
		return $this->report['shield']['method'];
	}

	/** The file we would write (.user.ini or .htaccess). */
	public function target() {
		return $this->target_file( $this->report['shield']['method'] );
	}

	/** Can the plugin write the shield itself here (vs. needing the host)? */
	public function can_autowrite() {
		$m = $this->report['shield']['method'];
		if ( 'snippet' === $m ) {
			return false;
		}
		return $this->files->writable( $this->target_file( $m ) );
	}

	/* ---- option storage (WP or in-memory for tests) -------------------- */

	protected function opt_get( $k ) {
		return p2s_opt_get( $k );
	}

	protected function opt_set( $k, $v ) {
		p2s_opt_set( $k, $v );
	}

	protected function opt_delete( $k ) {
		p2s_opt_delete( $k );
	}
}
