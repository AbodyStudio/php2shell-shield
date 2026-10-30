<?php
/**
 * Plugin Name:       PHP Defender – Old PHP Versions Shield
 * Plugin URI:        https://github.com/AbodyStudio/php2shell-shield
 * Description:        Reduces the risk of the PHP memory-corruption exploit known as PHP2Shell (CVE-2026-109618 / CVE-2026-109619) on sites that cannot update PHP yet. A shield, not a cure — the only real fix is updating PHP.
 * Version:           1.5.0
 * Requires at least: 3.6
 * Requires PHP:      7.0
 * Author:            AbodyStudio
 * Author URI:        https://abodystudio.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       php-defender
 *
 * NOTE: This file and the whole plugin must stay PHP 5.4 compatible,
 * because the oldest affected PHP version is 5.4. No arrow functions,
 * no null coalescing (??), no typed properties, no PHP 7+/8+ only calls.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'PHPDEF_VERSION', '1.5.0' );
define( 'PHPDEF_FILE', __FILE__ );
define( 'PHPDEF_DIR', plugin_dir_path( __FILE__ ) );
define( 'PHPDEF_URL', plugin_dir_url( __FILE__ ) );
define( 'PHPDEF_SLUG', 'php-defender' );

require_once PHPDEF_DIR . 'includes/compat.php';
require_once PHPDEF_DIR . 'includes/class-detect.php';
require_once PHPDEF_DIR . 'includes/class-files.php';
require_once PHPDEF_DIR . 'includes/class-shield.php';
require_once PHPDEF_DIR . 'includes/class-engine.php';
require_once PHPDEF_DIR . 'includes/class-edge.php';
require_once PHPDEF_DIR . 'includes/class-cloudflare.php';
require_once PHPDEF_DIR . 'includes/class-lockdown.php';
require_once PHPDEF_DIR . 'includes/class-scan.php';
require_once PHPDEF_DIR . 'includes/class-keys.php';
require_once PHPDEF_DIR . 'includes/class-secrets.php';
require_once PHPDEF_DIR . 'includes/class-phpready.php';
require_once PHPDEF_DIR . 'includes/class-phpswitch.php';

// The GitHub self-updater is only present in the GitHub distribution. The
// WordPress.org build omits this file so that updates come solely from
// WordPress.org, per the directory guidelines.
if ( file_exists( PHPDEF_DIR . 'includes/class-updater.php' ) ) {
	require_once PHPDEF_DIR . 'includes/class-updater.php';
}

/**
 * Writable directory for installed/updated rule packs (under uploads).
 * Returns '' when it cannot be determined; the built-in packs still work.
 *
 * @return string
 */
function phpdef_installed_packs_dir() {
	if ( function_exists( 'wp_upload_dir' ) ) {
		$u = wp_upload_dir();
		if ( empty( $u['error'] ) && ! empty( $u['basedir'] ) ) {
			return trailingslashit( $u['basedir'] ) . 'php-defender/packs/';
		}
	}
	return '';
}

/**
 * Shared rule-pack engine.
 *
 * @return Phpdef_Engine
 */
function phpdef_engine() {
	static $engine = null;
	if ( null === $engine ) {
		$engine = new Phpdef_Engine( PHPDEF_DIR . 'packs/', phpdef_installed_packs_dir() );
	}
	return $engine;
}

/**
 * Stored Cloudflare config (token stored obfuscated).
 *
 * @return array
 */
function phpdef_cf_config() {
	$c = phpdef_opt_get( 'phpdef_cf' );
	return is_array( $c ) ? $c : array();
}

/**
 * A Cloudflare client built from stored config, or null if not connected.
 *
 * @return Phpdef_Cloudflare|null
 */
function phpdef_cf_client() {
	$c = phpdef_cf_config();
	if ( empty( $c['token'] ) ) {
		return null;
	}
	$zone = isset( $c['zone_id'] ) ? $c['zone_id'] : '';
	return new Phpdef_Cloudflare( phpdef_deobfuscate( $c['token'] ), $zone );
}

// GitHub auto-updater with signed-download verification (GitHub build only).
if ( class_exists( 'Phpdef_Updater' ) ) {
	$GLOBALS['phpdef_updater'] = new Phpdef_Updater();
}

// PHP switcher — registers the verification probe endpoint used after a switch.
$GLOBALS['phpdef_phpswitch'] = new Phpdef_PhpSwitch();

if ( is_admin() ) {
	require_once PHPDEF_DIR . 'admin/class-admin.php';
	$GLOBALS['phpdef_admin'] = new Phpdef_Admin();
}

/**
 * Activation: store the version only. M0 writes nothing to the server.
 */
function phpdef_activate() {
	if ( false === get_option( 'phpdef_version' ) ) {
		add_option( 'phpdef_version', PHPDEF_VERSION );
	} else {
		update_option( 'phpdef_version', PHPDEF_VERSION );
	}
	// Mark that the setup wizard has not been completed yet.
	if ( false === get_option( 'phpdef_setup_done' ) ) {
		add_option( 'phpdef_setup_done', 0 );
	}
}
register_activation_hook( __FILE__, 'phpdef_activate' );
