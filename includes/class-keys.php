<?php
/**
 * Remote-access key audit for PHP2Shell Shield.
 *
 * Remote-management connectors are a master key to the whole site: whoever
 * holds the key can install plugins and run code. The UpdraftCentral incident
 * (October 2026) abused exactly this — valid keys used to push backdoors. This
 * lists the connectors installed on the site so the owner can see them and cut
 * any they do not recognise or need.
 *
 * Detection is by active connector plugin. Each entry carries how to revoke it;
 * the universal, reversible action the plugin offers is to deactivate the
 * connector plugin, which severs remote control immediately.
 *
 * The detection logic is pure (takes the active-plugin list) so it can be
 * tested from the CLI; deactivation uses WordPress and is guarded.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Keys {

	/**
	 * Known remote-management connectors.
	 *
	 * @return array
	 */
	public function connectors() {
		return array(
			array(
				'id'     => 'updraftcentral',
				'name'   => 'UpdraftCentral (UpdraftPlus)',
				'files'  => array( 'updraftplus/updraftplus.php' ),
				'revoke' => 'In UpdraftPlus &rarr; Advanced Tools &rarr; UpdraftCentral, remove any keys you do not recognise. UpdraftCentral keys were abused in October 2026 to plant backdoors.',
			),
			array(
				'id'     => 'managewp',
				'name'   => 'ManageWP Worker',
				'files'  => array( 'worker/init.php' ),
				'revoke' => 'Remove this site from your ManageWP dashboard, or deactivate the Worker plugin.',
			),
			array(
				'id'     => 'mainwp',
				'name'   => 'MainWP Child',
				'files'  => array( 'mainwp-child/mainwp-child.php' ),
				'revoke' => 'Disconnect the site in your MainWP dashboard, or deactivate the Child plugin.',
			),
			array(
				'id'     => 'infinitewp',
				'name'   => 'InfiniteWP Client',
				'files'  => array( 'iwp-client/init.php' ),
				'revoke' => 'Remove the site from your InfiniteWP panel, or deactivate the Client plugin.',
			),
			array(
				'id'     => 'jetpack',
				'name'   => 'Jetpack',
				'files'  => array( 'jetpack/jetpack.php' ),
				'revoke' => 'If you do not use Jetpack features, disconnect it under Jetpack &rarr; Settings, or deactivate it.',
			),
		);
	}

	/**
	 * Which connectors are active?
	 *
	 * @param array|null $active_plugins Override list (plugin basenames). When
	 *                                  null, read from WordPress.
	 * @return array Present connectors (each with id, name, plugin file, revoke).
	 */
	public function detect( $active_plugins = null ) {
		if ( null === $active_plugins ) {
			$active_plugins = $this->active_plugins();
		}
		$present = array();
		foreach ( $this->connectors() as $c ) {
			foreach ( $c['files'] as $file ) {
				if ( in_array( $file, $active_plugins, true ) ) {
					$c['plugin'] = $file;
					$present[]   = $c;
					break;
				}
			}
		}
		return $present;
	}

	protected function active_plugins() {
		if ( function_exists( 'get_option' ) ) {
			$a = get_option( 'active_plugins' );
			if ( is_array( $a ) ) {
				return $a;
			}
			// Also consider network-active plugins.
			if ( function_exists( 'get_site_option' ) ) {
				$n = get_site_option( 'active_sitewide_plugins' );
				if ( is_array( $n ) ) {
					return array_keys( $n );
				}
			}
		}
		return array();
	}

	/**
	 * Deactivate a connector by id (severs remote control). Reversible.
	 *
	 * @param string $id Connector id.
	 * @return array
	 */
	public function deactivate( $id ) {
		$target = null;
		foreach ( $this->connectors() as $c ) {
			if ( $c['id'] === $id ) {
				$target = $c;
				break;
			}
		}
		if ( null === $target ) {
			return array( 'ok' => false, 'reason' => 'unknown' );
		}
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			if ( defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
		}
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			return array( 'ok' => false, 'reason' => 'unavailable' );
		}
		$active = $this->active_plugins();
		foreach ( $target['files'] as $file ) {
			if ( in_array( $file, $active, true ) ) {
				deactivate_plugins( $file );
			}
		}
		return array( 'ok' => true, 'name' => $target['name'] );
	}
}
