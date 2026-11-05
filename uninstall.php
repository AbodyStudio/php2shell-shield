<?php
/**
 * Uninstall cleanup for AbodyStudio Shield.
 *
 * Removes the plugin's options. It intentionally does NOT remove any .htaccess
 * / .user.ini shield the user has turned on, because those protect the site and
 * should outlive the plugin until the user turns them off themselves. Turn the
 * shield, filter and lockdown OFF before deleting the plugin if you want them
 * removed.
 *
 * @package AbodyStudio_Shield
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$abody_options = array(
	'abody_version',
	'abody_setup_done',
	'abody_shield',
	'abody_backup',
	'abody_secrets_backup',
	'abody_edge',
	'abody_edge_allow',
	'abody_edge_backup',
	'abody_cf',
	'abody_lock',
	'abody_lock_backup',
	'abody_scan_result',
	'abody_phpcheck_result',
	'abody_phpswitch_backup',
);

foreach ( $abody_options as $abody_opt ) {
	delete_option( $abody_opt );
}
