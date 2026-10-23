<?php
/**
 * Uninstall cleanup for PHP2Shell Shield.
 *
 * Removes the plugin's options. It intentionally does NOT remove any .htaccess
 * / .user.ini shield the user has turned on, because those protect the site and
 * should outlive the plugin until the user turns them off themselves. Turn the
 * shield, filter and lockdown OFF before deleting the plugin if you want them
 * removed.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$p2s_options = array(
	'p2s_version',
	'p2s_setup_done',
	'p2s_shield',
	'p2s_backup',
	'p2s_edge',
	'p2s_edge_allow',
	'p2s_edge_backup',
	'p2s_cf',
	'p2s_lock',
	'p2s_lock_backup',
	'p2s_scan_result',
);

foreach ( $p2s_options as $p2s_opt ) {
	delete_option( $p2s_opt );
}
