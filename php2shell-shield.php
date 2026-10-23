<?php
/**
 * Plugin Name:       PHP2Shell Shield
 * Plugin URI:        https://github.com/AbodyStudio/php2shell-shield
 * Description:        Reduces the risk of the PHP2Shell exploit (CVE-2026-109618 / CVE-2026-109619) on sites that cannot update PHP yet. A shield, not a cure — the only real fix is updating PHP.
 * Version:           1.0.0
 * Requires at least: 5.0
 * Requires PHP:      5.4
 * Author:            AbodyStudio
 * Author URI:        https://abodystudio.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       php2shell-shield
 *
 * NOTE: This file and the whole plugin must stay PHP 5.4 compatible,
 * because the oldest affected PHP version is 5.4. No arrow functions,
 * no null coalescing (??), no typed properties, no PHP 7+/8+ only calls.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'P2S_VERSION', '1.0.0' );
define( 'P2S_FILE', __FILE__ );
define( 'P2S_DIR', plugin_dir_path( __FILE__ ) );
define( 'P2S_URL', plugin_dir_url( __FILE__ ) );
define( 'P2S_SLUG', 'php2shell-shield' );

require_once P2S_DIR . 'includes/compat.php';
require_once P2S_DIR . 'includes/class-detect.php';
require_once P2S_DIR . 'includes/class-files.php';
require_once P2S_DIR . 'includes/class-shield.php';
require_once P2S_DIR . 'includes/class-engine.php';
require_once P2S_DIR . 'includes/class-edge.php';
require_once P2S_DIR . 'includes/class-cloudflare.php';
require_once P2S_DIR . 'includes/class-lockdown.php';
require_once P2S_DIR . 'includes/class-scan.php';
require_once P2S_DIR . 'includes/class-keys.php';
require_once P2S_DIR . 'includes/class-secrets.php';

/**
 * Writable directory for installed/updated rule packs (under uploads).
 * Returns '' when it cannot be determined; the built-in packs still work.
 *
 * @return string
 */
function p2s_installed_packs_dir() {
	if ( function_exists( 'wp_upload_dir' ) ) {
		$u = wp_upload_dir();
		if ( empty( $u['error'] ) && ! empty( $u['basedir'] ) ) {
			return trailingslashit( $u['basedir'] ) . 'php2shell-shield/packs/';
		}
	}
	return '';
}

/**
 * Shared rule-pack engine.
 *
 * @return P2S_Engine
 */
function p2s_engine() {
	static $engine = null;
	if ( null === $engine ) {
		$engine = new P2S_Engine( P2S_DIR . 'packs/', p2s_installed_packs_dir() );
	}
	return $engine;
}

/**
 * Stored Cloudflare config (token stored obfuscated).
 *
 * @return array
 */
function p2s_cf_config() {
	$c = p2s_opt_get( 'p2s_cf' );
	return is_array( $c ) ? $c : array();
}

/**
 * A Cloudflare client built from stored config, or null if not connected.
 *
 * @return P2S_Cloudflare|null
 */
function p2s_cf_client() {
	$c = p2s_cf_config();
	if ( empty( $c['token'] ) ) {
		return null;
	}
	$zone = isset( $c['zone_id'] ) ? $c['zone_id'] : '';
	return new P2S_Cloudflare( p2s_deobfuscate( $c['token'] ), $zone );
}

if ( is_admin() ) {
	require_once P2S_DIR . 'admin/class-admin.php';
	$GLOBALS['p2s_admin'] = new P2S_Admin();
}

/**
 * Activation: store the version only. M0 writes nothing to the server.
 */
function p2s_activate() {
	if ( false === get_option( 'p2s_version' ) ) {
		add_option( 'p2s_version', P2S_VERSION );
	} else {
		update_option( 'p2s_version', P2S_VERSION );
	}
	// Mark that the setup wizard has not been completed yet.
	if ( false === get_option( 'p2s_setup_done' ) ) {
		add_option( 'p2s_setup_done', 0 );
	}
}
register_activation_hook( __FILE__, 'p2s_activate' );
