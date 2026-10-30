<?php
/**
 * Uninstall cleanup for PHP Defender.
 *
 * Removes the plugin's options. It intentionally does NOT remove any .htaccess
 * / .user.ini shield the user has turned on, because those protect the site and
 * should outlive the plugin until the user turns them off themselves. Turn the
 * shield, filter and lockdown OFF before deleting the plugin if you want them
 * removed.
 *
 * @package PHP_Defender
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$phpdef_options = array(
	'phpdef_version',
	'phpdef_setup_done',
	'phpdef_shield',
	'phpdef_backup',
	'phpdef_secrets_backup',
	'phpdef_edge',
	'phpdef_edge_allow',
	'phpdef_edge_backup',
	'phpdef_cf',
	'phpdef_lock',
	'phpdef_lock_backup',
	'phpdef_scan_result',
	'phpdef_phpcheck_result',
	'phpdef_phpswitch_backup',
);

foreach ( $phpdef_options as $phpdef_opt ) {
	delete_option( $phpdef_opt );
}
