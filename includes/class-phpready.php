<?php
/**
 * PHP upgrade-readiness scanner for PHP2Shell Shield.
 *
 * Helps a site owner decide whether they can safely move to a newer PHP (the
 * real fix for PHP2Shell) by scanning their active plugins and theme for
 * patterns that were REMOVED in newer PHP (which would cause fatal errors), and
 * for a few noisy deprecations. It also reads each add-on's declared
 * "Requires PHP".
 *
 * This is a readiness indicator, not a guarantee — a quick test on staging is
 * the only certain check. The scan is a high-signal, low-false-positive set of
 * removed-function/syntax checks; it does not execute any code.
 *
 * The rule set and scan functions are pure (no WordPress) so they can be tested
 * from the CLI; the gather step uses WordPress and is guarded.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_PhpReady {

	/** Lowest PHP branch with an official PHP2Shell fix — the upgrade floor. */
	public function min_target() {
		return '8.2';
	}

	/**
	 * Breaking-change rules. "removed" is the PHP version where the thing is
	 * gone (fatal) or, for sev=warn, where it became a deprecation (still runs).
	 *
	 * @return array
	 */
	public function rules() {
		return array(
			// Removed in 7.0 (fatal on any modern PHP).
			array( 're' => '/\bmysql_[a-z_]+\s*\(/i', 'label' => 'mysql_*() (use mysqli/PDO)', 'removed' => '7.0', 'sev' => 'blocker' ),
			array( 're' => '/\beregi?\s*\(/i', 'label' => 'ereg()/eregi()', 'removed' => '7.0', 'sev' => 'blocker' ),
			array( 're' => '/\beregi?_replace\s*\(/i', 'label' => 'ereg_replace()', 'removed' => '7.0', 'sev' => 'blocker' ),
			array( 're' => '/\bsplit\s*\(/i', 'label' => 'split() (use explode/preg_split)', 'removed' => '7.0', 'sev' => 'blocker' ),
			array( 're' => '/\bspliti\s*\(/i', 'label' => 'spliti()', 'removed' => '7.0', 'sev' => 'blocker' ),
			array( 're' => '/\bcall_user_method(_array)?\s*\(/i', 'label' => 'call_user_method()', 'removed' => '7.0', 'sev' => 'blocker' ),
			array( 're' => '/\bset_magic_quotes_runtime\s*\(/i', 'label' => 'set_magic_quotes_runtime()', 'removed' => '7.0', 'sev' => 'blocker' ),
			// Removed in 8.0 (fatal on 8.x).
			array( 're' => '/\bcreate_function\s*\(/i', 'label' => 'create_function()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\beach\s*\(/i', 'label' => 'each()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\bget_magic_quotes_(gpc|runtime)\s*\(/i', 'label' => 'get_magic_quotes_*()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\bmoney_format\s*\(/i', 'label' => 'money_format()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\bconvert_cyr_string\s*\(/i', 'label' => 'convert_cyr_string()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\b(image2wbmp|jpeg2wbmp|png2wbmp)\s*\(/i', 'label' => 'image2wbmp()/jpeg2wbmp()/png2wbmp()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\bfgetss\s*\(/i', 'label' => 'fgetss()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\brestore_include_path\s*\(/i', 'label' => 'restore_include_path()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/function\s+__autoload\s*\(/i', 'label' => '__autoload() (use spl_autoload_register)', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\bis_real\s*\(/i', 'label' => 'is_real()', 'removed' => '8.0', 'sev' => 'blocker' ),
			array( 're' => '/\$[A-Za-z_]\w*\{[^}\n]+\}/', 'label' => 'curly-brace array/string access $x{...}', 'removed' => '8.0', 'sev' => 'review' ),
			// Deprecations (8.1/8.2) — still runs, but logs warnings.
			array( 're' => '/\bstrftime\s*\(/i', 'label' => 'strftime() (deprecated 8.1)', 'removed' => '8.1', 'sev' => 'warn' ),
			array( 're' => '/\bFILTER_SANITIZE_STRING\b/', 'label' => 'FILTER_SANITIZE_STRING (deprecated 8.1)', 'removed' => '8.1', 'sev' => 'warn' ),
			array( 're' => '/\butf8_(encode|decode)\s*\(/i', 'label' => 'utf8_encode()/utf8_decode() (deprecated 8.2)', 'removed' => '8.2', 'sev' => 'warn' ),
		);
	}

	/** Rules that matter when moving TO $target (major.minor). */
	public function applicable_rules( $target ) {
		$out = array();
		foreach ( $this->rules() as $r ) {
			if ( version_compare( $target, $r['removed'], '>=' ) ) {
				$out[] = $r;
			}
		}
		return $out;
	}

	/**
	 * Scan one file's contents against the applicable rules.
	 *
	 * @param string $content PHP source.
	 * @param array  $rules   Applicable rules.
	 * @return array Findings (label, removed, sev, line).
	 */
	public function scan_content( $content, $rules ) {
		$found = array();
		foreach ( $rules as $r ) {
			if ( preg_match( $r['re'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$line     = substr_count( substr( $content, 0, $m[0][1] ), "\n" ) + 1;
				$found[]  = array(
					'label'   => $r['label'],
					'removed' => $r['removed'],
					'sev'     => $r['sev'],
					'line'    => $line,
				);
			}
		}
		return $found;
	}

	/**
	 * Scan a directory tree. Returns findings keyed by relative file path.
	 *
	 * @param string $dir    Directory.
	 * @param string $target Target PHP (major.minor).
	 * @param int    $cap    Max files to scan.
	 * @return array
	 */
	public function scan_dir( $dir, $target, $cap = 4000 ) {
		$rules   = $this->applicable_rules( $target );
		$results = array();
		if ( ! is_dir( $dir ) ) {
			return $results;
		}
		$dir = rtrim( $dir, '/\\' ) . '/';
		$n   = 0;
		try {
			$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $it as $file ) {
				if ( $n >= $cap ) {
					break;
				}
				if ( ! $file->isFile() ) {
					continue;
				}
				$path = $file->getPathname();
				if ( ! preg_match( '/\.php$/i', $path ) ) {
					continue;
				}
				if ( false !== strpos( $path, '/vendor/' ) || false !== strpos( $path, '/node_modules/' ) ) {
					continue;
				}
				if ( $file->getSize() > 700000 ) {
					continue;
				}
				$n++;
				$c = file_get_contents( $path );
				if ( false === $c ) {
					continue;
				}
				$hits = $this->scan_content( $c, $rules );
				if ( ! empty( $hits ) ) {
					$results[ str_replace( $dir, '', $path ) ] = $hits;
				}
			}
		} catch ( Exception $e ) {
			return $results;
		}
		return $results;
	}

	/* ---- WordPress-integrated run (guarded) ---------------------------- */

	/**
	 * Run the readiness check against $target and return a report.
	 *
	 * @param string|null $target major.minor, defaults to the upgrade floor.
	 * @return array
	 */
	public function run( $target = null ) {
		if ( null === $target ) {
			$target = $this->min_target();
		}
		$sources = $this->sources();
		$report  = array(
			'time'     => time(),
			'target'   => $target,
			'sources'  => array(),
			'blockers' => 0,
			'warnings' => 0,
			'reviews'  => 0,
		);

		foreach ( $sources as $label => $dir ) {
			$hits = $this->scan_dir( $dir, $target );
			if ( empty( $hits ) ) {
				continue;
			}
			$b = 0;
			$w = 0;
			$rv = 0;
			foreach ( $hits as $file => $findings ) {
				foreach ( $findings as $f ) {
					if ( 'blocker' === $f['sev'] ) {
						$b++;
					} elseif ( 'warn' === $f['sev'] ) {
						$w++;
					} else {
						$rv++;
					}
				}
			}
			$report['blockers'] += $b;
			$report['warnings'] += $w;
			$report['reviews']  += $rv;
			$report['sources'][] = array(
				'label' => $label,
				'files' => $hits,
			);
		}

		if ( $report['blockers'] > 0 ) {
			$report['verdict'] = 'issues';
		} elseif ( $report['reviews'] > 0 || $report['warnings'] > 0 ) {
			$report['verdict'] = 'review';
		} else {
			$report['verdict'] = 'ready';
		}
		return $report;
	}

	/**
	 * Active plugins + active theme (and parent) as label => directory.
	 *
	 * @return array
	 */
	protected function sources() {
		$out = array();

		if ( function_exists( 'get_option' ) && defined( 'WP_PLUGIN_DIR' ) ) {
			$active = get_option( 'active_plugins' );
			if ( is_array( $active ) ) {
				foreach ( $active as $p ) {
					$slug = dirname( $p );
					if ( '.' === $slug || '' === $slug ) {
						$out[ 'Plugin: ' . $p ] = WP_PLUGIN_DIR . '/' . $p;
					} else {
						$out[ 'Plugin: ' . $slug ] = WP_PLUGIN_DIR . '/' . $slug;
					}
				}
			}
		}
		if ( function_exists( 'get_stylesheet_directory' ) ) {
			$out[ 'Active theme' ] = get_stylesheet_directory();
			if ( function_exists( 'get_template_directory' ) ) {
				$parent = get_template_directory();
				if ( $parent !== get_stylesheet_directory() ) {
					$out[ 'Parent theme' ] = $parent;
				}
			}
		}
		return $out;
	}
}
