<?php
/**
 * Environment detection for PHP2Shell Shield.
 *
 * Read-only. Figures out the PHP version, how PHP runs (SAPI), the web
 * server, whether a proxy like Cloudflare is in front, which shield method
 * applies, whether the mitigations are already in effect, and an overall
 * exposure status.
 *
 * Deliberately has NO WordPress dependency so it can be unit-tested from the
 * CLI. Pass a $ctx array to override the live environment for testing.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'P2S_STANDALONE' ) ) {
	exit;
}

class P2S_Detect {

	/**
	 * Fixed PHP release per branch (CVE-2026-109618 / -109619, "PHP2Shell").
	 * Branches not listed have NO upstream fix (end of life); a host may still
	 * backport one, which we cannot tell from the version number alone.
	 *
	 * @var array
	 */
	protected $fixed = array(
		'8.5' => '8.5.12',
		'8.4' => '8.4.27',
		'8.3' => '8.3.36',
		'8.2' => '8.2.35',
	);

	/**
	 * Optional context overrides for testing.
	 *
	 * @var array
	 */
	protected $ctx;

	/**
	 * @param array      $ctx       Optional overrides: php_version, sapi,
	 *                              server_software, cf, xff, memory_limit,
	 *                              upload_progress.
	 * @param array|null $fixed_map Optional fixed-version map from the rule
	 *                              pack (branch => fixed version). Falls back to
	 *                              the built-in map so detection never breaks.
	 */
	public function __construct( $ctx = array(), $fixed_map = null ) {
		$this->ctx = is_array( $ctx ) ? $ctx : array();
		if ( is_array( $fixed_map ) && ! empty( $fixed_map ) ) {
			$this->fixed = $fixed_map;
		}
	}

	/**
	 * Run the full detection and return a structured report.
	 *
	 * @return array
	 */
	public function run() {
		$php    = $this->detect_php();
		$server = $this->detect_server();
		$proxy  = $this->detect_proxy();
		$shield = $this->detect_shield_method( $php, $server );
		$mit    = $this->detect_mitigations();
		$status = $this->compute_status( $php, $shield, $mit );

		return array(
			'php'         => $php,
			'server'      => $server,
			'proxy'       => $proxy,
			'shield'      => $shield,
			'mitigations' => $mit,
			'status'      => $status,
		);
	}

	/* ------------------------------------------------------------------ */

	protected function ctx( $key, $default = null ) {
		if ( array_key_exists( $key, $this->ctx ) ) {
			return $this->ctx[ $key ];
		}
		return $default;
	}

	protected function detect_php() {
		$version = $this->ctx( 'php_version', PHP_VERSION );
		$parts   = explode( '.', $version );
		$major   = isset( $parts[0] ) ? (int) $parts[0] : 0;
		$minor   = isset( $parts[1] ) ? (int) $parts[1] : 0;
		$branch  = $major . '.' . $minor;

		$sapi = $this->ctx( 'sapi', php_sapi_name() );

		$has_fix       = isset( $this->fixed[ $branch ] );
		$fixed_version = $has_fix ? $this->fixed[ $branch ] : null;
		$is_fixed      = $has_fix ? ( version_compare( $version, $fixed_version, '>=' ) ) : false;

		return array(
			'version'          => $version,
			'branch'           => $branch,
			'sapi'             => $sapi,
			'sapi_label'       => $this->sapi_label( $sapi ),
			'has_upstream_fix' => $has_fix,
			'fixed_version'    => $fixed_version,
			'is_fixed'         => $is_fixed,
			'affected'         => ! $is_fixed,
		);
	}

	protected function sapi_label( $sapi ) {
		$map = array(
			'fpm-fcgi'       => 'PHP-FPM (FastCGI)',
			'cgi-fcgi'       => 'CGI / FastCGI',
			'apache2handler' => 'Apache module (mod_php)',
			'litespeed'      => 'LiteSpeed (LSAPI)',
			'cli'            => 'Command line',
			'cli-server'     => 'Built-in server',
		);
		if ( isset( $map[ $sapi ] ) ) {
			return $map[ $sapi ];
		}
		return $sapi ? $sapi : 'Unknown';
	}

	protected function detect_server() {
		$sw = $this->ctx( 'server_software', p2s_server( 'SERVER_SOFTWARE', '' ) );

		$type  = 'unknown';
		$label = 'Unknown';
		if ( p2s_str_contains( $sw, 'litespeed' ) ) {
			$type  = 'litespeed';
			$label = 'LiteSpeed';
		} elseif ( p2s_str_contains( $sw, 'apache' ) ) {
			$type  = 'apache';
			$label = 'Apache';
		} elseif ( p2s_str_contains( $sw, 'nginx' ) ) {
			$type  = 'nginx';
			$label = 'NGINX';
		} elseif ( p2s_str_contains( $sw, 'microsoft-iis' ) || p2s_str_contains( $sw, 'iis' ) ) {
			$type  = 'iis';
			$label = 'Microsoft IIS';
		}

		return array(
			'software' => $sw ? $sw : 'Unknown',
			'type'     => $type,
			'label'    => $label,
		);
	}

	protected function detect_proxy() {
		$cf = $this->ctx( 'cf', null );
		if ( null === $cf ) {
			$cf = ( '' !== p2s_server( 'HTTP_CF_RAY', '' ) ) || ( '' !== p2s_server( 'HTTP_CF_CONNECTING_IP', '' ) );
		}
		$xff = $this->ctx( 'xff', null );
		if ( null === $xff ) {
			$xff = ( '' !== p2s_server( 'HTTP_X_FORWARDED_FOR', '' ) );
		}

		$label = 'None detected';
		if ( $cf ) {
			$label = 'Cloudflare';
		} elseif ( $xff ) {
			$label = 'A proxy / CDN (not Cloudflare)';
		}

		return array(
			'cloudflare' => (bool) $cf,
			'other'      => ( ! $cf && $xff ),
			'label'      => $label,
		);
	}

	/**
	 * Which method can this environment use to apply the pre-PHP ini shield,
	 * and the request filter?
	 *
	 * Key nuance: .user.ini is a PHP (FastCGI/FPM) feature, read by PHP itself
	 * regardless of the web server. So nginx + PHP-FPM CAN use .user.ini even
	 * though it ignores .htaccess. mod_php (apache2handler) does NOT read
	 * .user.ini and must use .htaccess php_value instead.
	 */
	protected function detect_shield_method( $php, $server ) {
		$sapi = $php['sapi'];

		$user_ini = in_array( $sapi, array( 'fpm-fcgi', 'cgi-fcgi', 'litespeed' ), true );
		// LiteSpeed honours .htaccess php_value; so does classic mod_php.
		$htaccess_php = ( 'apache2handler' === $sapi ) || ( 'litespeed' === $server['type'] );
		// Request-filter rewrite rules via .htaccess work on Apache and LiteSpeed.
		$htaccess_rewrite = in_array( $server['type'], array( 'apache', 'litespeed' ), true );

		if ( $user_ini ) {
			$method       = 'user_ini';
			$method_label = '.user.ini (read by PHP before your code runs)';
		} elseif ( $htaccess_php ) {
			$method       = 'htaccess';
			$method_label = '.htaccess php_value';
		} else {
			$method       = 'snippet';
			$method_label = 'host-side config snippet (we cannot write it for you)';
		}

		return array(
			'user_ini_supported'      => $user_ini,
			'htaccess_php_supported'  => $htaccess_php,
			'htaccess_rewrite'        => $htaccess_rewrite,
			'can_self_shield'         => ( $user_ini || $htaccess_php ),
			'method'                  => $method,
			'method_label'            => $method_label,
			'user_ini_ttl'            => (int) $this->ini_number( 'user_ini.cache_ttl', 300 ),
		);
	}

	protected function detect_mitigations() {
		$mem_raw = $this->ctx( 'memory_limit', ini_get( 'memory_limit' ) );
		$up_raw  = $this->ctx( 'upload_progress', ini_get( 'session.upload_progress.enabled' ) );

		$mem_ok = ( '-1' === trim( (string) $mem_raw ) );
		$up_ok  = ! p2s_ini_truthy( $up_raw );

		return array(
			'memory_limit'    => array(
				'current' => ( '' === (string) $mem_raw ) ? 'not set' : (string) $mem_raw,
				'target'  => '-1',
				'ok'      => $mem_ok,
			),
			'upload_progress' => array(
				'current' => p2s_ini_truthy( $up_raw ) ? 'on' : 'off',
				'target'  => 'off',
				'ok'      => $up_ok,
			),
			'all_ok'          => ( $mem_ok && $up_ok ),
		);
	}

	protected function compute_status( $php, $shield, $mit ) {
		if ( $php['is_fixed'] ) {
			return $this->status(
				'patched',
				'Patched',
				'Your PHP is a fixed version. The PHP2Shell bug itself is closed. You can keep the shield on as extra defence, but you are no longer exposed to it.'
			);
		}

		$notes = array();
		if ( ! $php['has_upstream_fix'] ) {
			$notes[] = 'Your PHP branch (' . $php['branch'] . ') has no official fix. Your host may have backported one while keeping this version number — check with them. Otherwise the shield and updating PHP are your options.';
		} else {
			$notes[] = 'Your version looks older than ' . $php['fixed_version'] . ', but some hosts backport the fix while keeping the version number. If unsure, confirm with your host.';
		}

		if ( $mit['all_ok'] ) {
			return $this->status(
				'shielded',
				'Shielded',
				'The stopgap settings are in effect, so the known attack paths are blunted. This is not a full fix — update PHP to ' . ( $php['fixed_version'] ? $php['fixed_version'] : 'a supported, fixed version' ) . ' when you can.',
				$notes
			);
		}

		if ( ! $shield['can_self_shield'] ) {
			$notes[] = 'On ' . '(this SAPI) ' . 'the plugin cannot write the shield itself; it will give you a snippet to hand to your host.';
			return $this->status(
				'needs_host',
				'Needs host action',
				'This server needs a change the plugin cannot make on its own. The plugin will generate the exact snippet for your host.',
				$notes
			);
		}

		return $this->status(
			'exposed',
			'Exposed',
			'This site is running an affected PHP version with no mitigation in place. Turn on the shield, and update PHP when you can.',
			$notes
		);
	}

	protected function status( $code, $label, $summary, $notes = array() ) {
		return array(
			'code'    => $code,
			'label'   => $label,
			'summary' => $summary,
			'notes'   => $notes,
		);
	}

	/**
	 * Read a numeric ini value with a fallback, test-overridable.
	 */
	protected function ini_number( $key, $default ) {
		$ctx_key = str_replace( '.', '_', $key );
		$val     = $this->ctx( $ctx_key, ini_get( $key ) );
		if ( false === $val || '' === $val || null === $val ) {
			return $default;
		}
		return $val;
	}
}
