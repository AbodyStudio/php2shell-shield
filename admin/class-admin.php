<?php
/**
 * Admin UI for PHP2Shell Shield — modern, visual dashboard.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Admin {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_p2s_enable', array( $this, 'handle_enable' ) );
		add_action( 'admin_post_p2s_disable', array( $this, 'handle_disable' ) );
		add_action( 'admin_post_p2s_edge_enable', array( $this, 'handle_edge_enable' ) );
		add_action( 'admin_post_p2s_edge_disable', array( $this, 'handle_edge_disable' ) );
		add_action( 'admin_post_p2s_edge_allow', array( $this, 'handle_edge_allow' ) );
		add_action( 'admin_post_p2s_cf_connect', array( $this, 'handle_cf_connect' ) );
		add_action( 'admin_post_p2s_cf_disconnect', array( $this, 'handle_cf_disconnect' ) );
		add_action( 'admin_post_p2s_cf_deploy', array( $this, 'handle_cf_deploy' ) );
		add_action( 'admin_post_p2s_cf_remove', array( $this, 'handle_cf_remove' ) );
		add_action( 'admin_post_p2s_lock_enable', array( $this, 'handle_lock_enable' ) );
		add_action( 'admin_post_p2s_lock_disable', array( $this, 'handle_lock_disable' ) );
		add_action( 'admin_post_p2s_scan_run', array( $this, 'handle_scan_run' ) );
		add_action( 'admin_post_p2s_key_deactivate', array( $this, 'handle_key_deactivate' ) );
		add_action( 'admin_post_p2s_secrets_rotate', array( $this, 'handle_secrets_rotate' ) );
	}

	public function menu() {
		add_menu_page(
			'PHP2Shell Shield',
			'PHP2Shell Shield',
			'manage_options',
			P2S_SLUG,
			array( $this, 'render' ),
			$this->menu_icon(),
			81
		);
	}

	/** A green shield (with a check knocked out) as the admin menu icon. */
	protected function menu_icon() {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">'
			. '<path fill="#3fb950" fill-rule="evenodd" d="M10 1 L3 3.5 V9.3 C3 13.6 6 17.2 10 18.5 C14 17.2 17 13.6 17 9.3 V3.5 Z '
			. 'M8.9 13 L5.4 9.5 L6.8 8.1 L8.9 10.2 L13.2 5.9 L14.6 7.3 Z"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg );
	}

	public function assets( $hook ) {
		if ( 'toplevel_page_' . P2S_SLUG !== $hook ) {
			return;
		}
		wp_register_style( 'p2s-admin', false, array(), P2S_VERSION );
		wp_enqueue_style( 'p2s-admin' );
		wp_add_inline_style( 'p2s-admin', $this->css() );
	}

	/* ---- action handlers ---------------------------------------------- */

	protected function back( $notice ) {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'       => P2S_SLUG,
					'p2s_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	public function handle_enable() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'p2s_enable' );
		$ini    = function_exists( 'p2s_engine' ) ? p2s_engine()->mitigation_ini() : null;
		$shield = new P2S_Shield( null, null, $ini );
		$res    = $shield->enable();
		if ( ! empty( $res['ok'] ) ) {
			$this->back( 'enabled' );
		}
		$reason = isset( $res['reason'] ) ? $res['reason'] : 'unknown';
		$this->back( 'enable_failed_' . $reason );
	}

	public function handle_disable() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'p2s_disable' );
		$shield = new P2S_Shield();
		$shield->disable();
		$this->back( 'disabled' );
	}

	/* ---- edge filter --------------------------------------------------- */

	protected function guard( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( $nonce );
	}

	public function handle_edge_enable() {
		$this->guard( 'p2s_edge' );
		$edge = new P2S_Edge( null, $this->detect_report() );
		$res  = $edge->enable_htaccess();
		$this->back( ! empty( $res['ok'] ) ? 'edge_on' : 'edge_fail' );
	}

	public function handle_edge_disable() {
		$this->guard( 'p2s_edge' );
		$edge = new P2S_Edge( null, $this->detect_report() );
		$edge->disable_htaccess();
		$this->back( 'edge_off' );
	}

	public function handle_edge_allow() {
		$this->guard( 'p2s_edge_allow' );
		$raw  = isset( $_POST['allow'] ) ? wp_unslash( $_POST['allow'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$list = preg_split( '/[\r\n]+/', (string) $raw );
		$edge = new P2S_Edge( null, $this->detect_report() );
		$edge->set_allowlist( $list );
		if ( $edge->is_active() ) {
			$edge->enable_htaccess();
		}
		$this->back( 'edge_allow' );
	}

	/* ---- cloudflare ---------------------------------------------------- */

	public function handle_cf_connect() {
		$this->guard( 'p2s_cf' );
		$token = isset( $_POST['cf_token'] ) ? trim( (string) wp_unslash( $_POST['cf_token'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( '' === $token ) {
			$this->back( 'cf_fail' );
		}
		$cf  = new P2S_Cloudflare( $token );
		$ver = $cf->verify_token();
		if ( empty( $ver['ok'] ) ) {
			$this->back( 'cf_badtoken' );
		}
		$host = (string) parse_url( home_url(), PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- core parse_url keeps PHP 4.0+ support.
		$zone = $cf->find_zone( $host );
		if ( empty( $zone['ok'] ) ) {
			$this->back( 'cf_nozone' );
		}
		p2s_opt_set(
			'p2s_cf',
			array(
				'token'     => p2s_obfuscate( $token ),
				'zone_id'   => $zone['zone_id'],
				'domain'    => $host,
				'connected' => 1,
			)
		);
		$this->back( 'cf_connected' );
	}

	public function handle_cf_disconnect() {
		$this->guard( 'p2s_cf' );
		$cf = p2s_cf_client();
		if ( $cf ) {
			$cf->remove_rule( 'p2s:filter' );
		}
		p2s_opt_delete( 'p2s_cf' );
		$this->back( 'cf_disconnected' );
	}

	public function handle_cf_deploy() {
		$this->guard( 'p2s_cf' );
		$cf = p2s_cf_client();
		if ( ! $cf ) {
			$this->back( 'cf_fail' );
		}
		$edge = new P2S_Edge( null, $this->detect_report() );
		$res  = $cf->deploy_rule( 'p2s:filter', $edge->cf_expression(), 'block' );
		if ( ! empty( $res['ok'] ) ) {
			$c            = p2s_cf_config();
			$c['rule_on'] = 1;
			p2s_opt_set( 'p2s_cf', $c );
		}
		$this->back( ! empty( $res['ok'] ) ? 'cf_deployed' : 'cf_fail' );
	}

	public function handle_cf_remove() {
		$this->guard( 'p2s_cf' );
		$cf = p2s_cf_client();
		if ( $cf ) {
			$cf->remove_rule( 'p2s:filter' );
			$c            = p2s_cf_config();
			$c['rule_on'] = 0;
			p2s_opt_set( 'p2s_cf', $c );
		}
		$this->back( 'cf_removed' );
	}

	/* ---- lockdown ------------------------------------------------------ */

	public function handle_lock_enable() {
		$this->guard( 'p2s_lock' );
		$ips = array( p2s_remote_addr() );
		if ( isset( $_POST['extra_ip'] ) ) {
			$extra = trim( (string) wp_unslash( $_POST['extra_ip'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( '' !== $extra ) {
				$ips[] = $extra;
			}
		}
		$lock = new P2S_Lockdown();
		$res  = $lock->enable( $ips );
		$this->back( ! empty( $res['ok'] ) ? 'lock_on' : 'lock_fail' );
	}

	public function handle_lock_disable() {
		$this->guard( 'p2s_lock' );
		$lock = new P2S_Lockdown();
		$lock->disable();
		$this->back( 'lock_off' );
	}

	protected function detect_report() {
		$engine = function_exists( 'p2s_engine' ) ? p2s_engine() : new P2S_Engine( P2S_DIR . 'packs/' );
		$d      = new P2S_Detect( array(), $engine->php_fixed_map() );
		return $d->run();
	}

	/* ---- breach check -------------------------------------------------- */

	public function handle_scan_run() {
		$this->guard( 'p2s_scan' );
		$scan = new P2S_Scan();
		p2s_opt_set( 'p2s_scan_result', $scan->run() );
		$this->back( 'scan_done' );
	}

	public function handle_key_deactivate() {
		$this->guard( 'p2s_keys' );
		$id   = isset( $_POST['key_id'] ) ? sanitize_key( wp_unslash( $_POST['key_id'] ) ) : '';
		$keys = new P2S_Keys();
		$keys->deactivate( $id );
		$this->back( 'key_off' );
	}

	public function handle_secrets_rotate() {
		$this->guard( 'p2s_secrets' );
		$secrets = new P2S_Secrets();
		$res     = $secrets->rotate_file();
		$this->back( ! empty( $res['ok'] ) ? 'secrets_done' : 'secrets_fail' );
	}

	/* ---- notices ------------------------------------------------------- */

	protected function notice() {
		if ( ! isset( $_GET['p2s_notice'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$n = sanitize_text_field( wp_unslash( $_GET['p2s_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( 'enabled' === $n ) {
			$this->admin_box( 'success', 'Protection turned on. The settings were written. PHP may take a few minutes to pick them up on some servers — re-scan to confirm.' );
		} elseif ( 'disabled' === $n ) {
			$this->admin_box( 'info', 'Protection turned off. Your original configuration was restored.' );
		} elseif ( 'enable_failed_not_writable' === $n ) {
			$this->admin_box( 'error', 'The plugin could not write the config file (the server blocked it). Use the manual snippet, or ask your host to apply it.' );
		} elseif ( 'enable_failed_snippet_only' === $n ) {
			$this->admin_box( 'error', 'This server type needs a host-side change. Use the manual snippet.' );
		} elseif ( 0 === strpos( $n, 'enable_failed' ) ) {
			$this->admin_box( 'error', 'Protection could not be turned on automatically. Use the manual snippet.' );
		} elseif ( 'edge_on' === $n ) {
			$this->admin_box( 'success', 'Edge filter turned on. Please test your site\'s forms and uploads — if anything stops working, add its path to the allowlist or turn the filter off.' );
		} elseif ( 'edge_off' === $n ) {
			$this->admin_box( 'info', 'Edge filter turned off.' );
		} elseif ( 'edge_allow' === $n ) {
			$this->admin_box( 'success', 'Allowlist saved.' );
		} elseif ( 'edge_fail' === $n ) {
			$this->admin_box( 'error', 'Could not write the edge filter here. Use the nginx snippet, or ask your host.' );
		} elseif ( 'cf_connected' === $n ) {
			$this->admin_box( 'success', 'Connected to Cloudflare.' );
		} elseif ( 'cf_disconnected' === $n ) {
			$this->admin_box( 'info', 'Disconnected from Cloudflare and removed our rule.' );
		} elseif ( 'cf_deployed' === $n ) {
			$this->admin_box( 'success', 'Edge rule deployed to Cloudflare. Test your forms and uploads.' );
		} elseif ( 'cf_removed' === $n ) {
			$this->admin_box( 'info', 'Removed our Cloudflare rule.' );
		} elseif ( 'cf_badtoken' === $n ) {
			$this->admin_box( 'error', 'Cloudflare rejected that API token. Check it has Zone WAF edit permission.' );
		} elseif ( 'cf_nozone' === $n ) {
			$this->admin_box( 'error', 'Connected, but this site\'s domain was not found in that Cloudflare account.' );
		} elseif ( 0 === strpos( $n, 'cf_' ) ) {
			$this->admin_box( 'error', 'Cloudflare action failed. Please try again.' );
		} elseif ( 'lock_on' === $n ) {
			$this->admin_box( 'success', 'Lockdown is ON. The site is reachable only from your allowed IP(s); everyone else sees the maintenance page.' );
		} elseif ( 'lock_off' === $n ) {
			$this->admin_box( 'info', 'Lockdown turned off. The site is back online.' );
		} elseif ( 'lock_fail' === $n ) {
			$this->admin_box( 'error', 'Could not enable lockdown (could not write .htaccess, or no valid IP).' );
		} elseif ( 'scan_done' === $n ) {
			$this->admin_box( 'success', 'Scan complete. Results are below.' );
		} elseif ( 'key_off' === $n ) {
			$this->admin_box( 'success', 'Remote connection deactivated.' );
		} elseif ( 'secrets_done' === $n ) {
			$this->admin_box( 'success', 'Security keys rotated. Everyone (including you) has been signed out — log in again. Stolen session cookies no longer work.' );
		} elseif ( 'secrets_fail' === $n ) {
			$this->admin_box( 'error', 'Could not rotate the keys automatically (wp-config.php may not be writable, or the keys are defined elsewhere). Nothing was changed.' );
		}
	}

	protected function admin_box( $type, $msg ) {
		echo '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
	}

	/* ---- helpers ------------------------------------------------------- */

	protected function tone( $code ) {
		$map = array(
			'patched'    => 'ok',
			'shielded'   => 'warn',
			'exposed'    => 'bad',
			'needs_host' => 'warn',
			'unknown'    => 'warn',
		);
		return isset( $map[ $code ] ) ? $map[ $code ] : 'warn';
	}

	/** Inline feather-style icon by name, coloured via currentColor. */
	protected function icon( $name ) {
		$paths = array(
			'shield'  => '<path d="M12 2 L4 5 V11 C4 16.2 7.4 20.6 12 22 C16.6 20.6 20 16.2 20 11 V5 Z"/><path d="M8.5 11.8 L11 14.3 L15.8 9"/>',
			'zap'     => '<path d="M13 2 L3 14 h9 l-1 8 10-12 h-9 l1-8 z"/>',
			'cloud'   => '<path d="M18 10 h-1.26 A8 8 0 1 0 9 20 h9 a5 5 0 0 0 0-10 z"/>',
			'lock'    => '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11 V7 a5 5 0 0 1 10 0 v4"/>',
			'search'  => '<circle cx="11" cy="11" r="8"/><path d="M21 21 l-4.35-4.35"/>',
			'key'     => '<circle cx="8" cy="15" r="4"/><path d="M11 12 L20 3 M18 5 L21 8 M15 8 L18 11"/>',
			'refresh' => '<path d="M23 4 v6 h-6 M1 20 v-6 h6"/><path d="M3.5 9 a9 9 0 0 1 14.9-3.4 L23 10 M1 14 l4.6 4.4 A9 9 0 0 0 20.5 15"/>',
			'server'  => '<rect x="2" y="4" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="6" rx="2"/><path d="M6 8 h.01 M6 17 h.01"/>',
			'file'    => '<path d="M14 2 H6 a2 2 0 0 0-2 2 v16 a2 2 0 0 0 2 2 h12 a2 2 0 0 0 2-2 V8 z"/><path d="M14 2 v6 h6"/>',
			'eye'     => '<path d="M1 12 s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8 z"/><circle cx="12" cy="12" r="3"/>',
			'globe'   => '<circle cx="12" cy="12" r="9"/><path d="M3 12 h18 M12 3 a15 15 0 0 1 0 18 M12 3 a15 15 0 0 0 0 18"/>',
			'code'    => '<path d="M8 6 l-5 6 5 6 M16 6 l5 6-5 6 M13 4 l-2 16"/>',
			'wp'      => '<circle cx="12" cy="12" r="9"/><path d="M12 3 c3 3 3 15 0 18 M12 3 c-3 3-3 15 0 18 M3.5 9 h17 M3.5 15 h17"/>',
		);
		$p = isset( $paths[ $name ] ) ? $paths[ $name ] : $paths['shield'];
		return '<span class="p2s-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $p . '</svg></span>';
	}

	/** Big green shield logo for the hero. */
	protected function logo_svg() {
		return '<svg class="p2s-logo" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
			. '<path d="M12 2 L4 5 V11 C4 16.2 7.4 20.6 12 22 C16.6 20.6 20 16.2 20 11 V5 Z"/>'
			. '<path d="M8.5 11.8 L11 14.3 L15.8 9" stroke-width="2.2"/></svg>';
	}

	protected function card_head( $icon, $title, $badge = '' ) {
		echo '<div class="p2s-head">' . $this->icon( $icon ) . '<h2>' . esc_html( $title ) . '</h2>' . $badge . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- icon + pre-escaped badge.
	}

	protected function group_title( $txt ) {
		echo '<h2 class="p2s-group">' . esc_html( $txt ) . '</h2>';
	}

	protected function pill( $tone, $txt ) {
		return ' <span class="p2s-pill p2s-' . esc_attr( $tone ) . '">' . esc_html( $txt ) . '</span>';
	}

	protected function snippet_box( $text ) {
		$rows = substr_count( $text, "\n" ) + 1;
		echo '<textarea class="p2s-snippet" rows="' . esc_attr( (string) $rows ) . '" readonly="readonly" onclick="this.select()"'
			. ' style="width:100%;box-sizing:border-box;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;line-height:1.55;background:#0b0f10;color:#7ee787;border:1px solid #30363d;border-radius:10px;padding:14px;box-shadow:inset 0 1px 3px rgba(0,0,0,.45)">'
			. esc_textarea( $text ) . '</textarea>';
	}

	protected function how_it_works() {
		$steps = array(
			array( 'search', '1 · We check', 'We read your PHP, server and settings and tell you plainly whether you are at risk — no guesswork.' ),
			array( 'shield', '2 · We shield', 'We place the fix where the attack happens — before PHP runs — so even a site that can\'t update PHP is protected.' ),
			array( 'eye', '3 · We watch', 'We scan for break-ins, list anyone holding a master key to your site, and let you lock it down in one click.' ),
		);
		echo '<div class="p2s-how">';
		foreach ( $steps as $s ) {
			echo '<div class="p2s-step"><div class="p2s-step-ic">' . $this->icon( $s[0] ) . '</div>';
			echo '<h3>' . esc_html( $s[1] ) . '</h3><p>' . esc_html( $s[2] ) . '</p></div>';
		}
		echo '</div>';
	}

	/* ---- render -------------------------------------------------------- */

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$engine = function_exists( 'p2s_engine' ) ? p2s_engine() : new P2S_Engine( P2S_DIR . 'packs/' );
		$detect = new P2S_Detect( array(), $engine->php_fixed_map() );
		$r      = $detect->run();
		$shield = new P2S_Shield( null, $r, $engine->mitigation_ini() );
		$v      = $shield->verify();
		$edge   = new P2S_Edge( null, $r );
		$lock   = new P2S_Lockdown();
		$cfg    = function_exists( 'p2s_cf_config' ) ? p2s_cf_config() : array();
		$tone   = $this->tone( $r['status']['code'] );

		$layers = array( $shield->is_active(), $edge->is_active(), ! empty( $cfg['rule_on'] ), $lock->is_active() );
		$on     = 0;
		foreach ( $layers as $L ) {
			if ( $L ) {
				$on++;
			}
		}
		$pct = (int) round( $on / 4 * 100 );

		echo '<div class="wrap p2s-wrap">';

		/* Hero: shield core + status + layers */
		echo '<div class="p2s-core p2s-' . esc_attr( $tone ) . '">';
		echo '<div class="p2s-reactor"><span class="rr r1"></span><span class="rr r2"></span><span class="rr r3"></span><span class="sweep"></span><span class="score">' . $this->logo_svg() . '</span></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static SVG.
		echo '<div class="p2s-core-read">';
		echo '<div class="p2s-eyebrow"><span class="pulse"></span> PHP2Shell &middot; CVE-2026-109618 / 109619</div>';
		echo '<div class="p2s-word">' . esc_html( $r['status']['label'] ) . '</div>';
		echo '<p>' . esc_html( $r['status']['summary'] ) . '</p>';
		if ( ! empty( $r['status']['notes'] ) ) {
			echo '<ul class="p2s-notes">';
			foreach ( $r['status']['notes'] as $note ) {
				echo '<li>' . esc_html( $note ) . '</li>';
			}
			echo '</ul>';
		}
		echo '<div class="p2s-layers"><div class="bar"><i style="width:' . esc_attr( (string) $pct ) . '%"></i></div>';
		echo '<div class="llbl"><span>Protection layers</span><span>' . (int) $on . ' of 4 active</span></div></div>';
		echo '<div class="p2s-chips">';
		echo '<span class="pc">PHP ' . esc_html( $r['php']['version'] ) . ' ' . ( $r['php']['is_fixed'] ? '<b class="ok">fixed</b>' : '<b class="bad">affected</b>' ) . '</span>';
		echo '<span class="pc">' . esc_html( $r['server']['label'] ) . '</span>';
		echo '<span class="pc">' . esc_html( $r['proxy']['label'] ) . '</span>';
		echo '</div>';
		echo '</div></div>';

		$this->notice();

		/* Honesty */
		echo '<div class="p2s-honest"><strong>This is risk reduction, not a true fix.</strong> ';
		echo 'The only real fix for PHP2Shell is updating PHP to a fixed version';
		if ( $r['php']['fixed_version'] ) {
			echo ' (' . esc_html( $r['php']['fixed_version'] ) . ' for your branch)';
		}
		echo '. The shield lowers your risk and tells you if you were already hit. It cannot make an unpatched server perfectly safe.</div>';

		/* Defense pipeline (reflects real state) */
		$this->render_pipeline( $shield->is_active(), ! empty( $cfg['rule_on'] ), $r );

		/* Primary action */
		$this->render_control( $shield, $v );

		/* How it works */
		$this->group_title( 'How it works' );
		$this->how_it_works();

		/* More protection */
		$this->group_title( 'More protection' );
		$this->render_edge( $edge, $r );
		$this->render_cloudflare( $r );
		$this->render_lockdown( $lock, $r );

		/* Check & recover */
		$this->group_title( 'Check & recover' );
		$this->render_keys();
		$this->render_scan();
		$this->render_secrets();

		/* Details */
		$this->group_title( 'Details' );
		$this->render_environment( $r );
		$this->render_pack( $engine );
		$this->render_snippet( $shield );

		echo '<p class="p2s-foot">PHP2Shell Shield &middot; by <a href="https://abodystudio.com" target="_blank" rel="noopener">AbodyStudio</a> &middot; <a href="mailto:support@abodystudio.com">support@abodystudio.com</a></p>';

		echo '</div>';
	}

	protected function pipe_node( $icon, $name, $desc, $on, $guard = false ) {
		$cls = 'p2s-node' . ( $guard ? ' guard' : '' ) . ( $on ? ' on' : '' );
		echo '<div class="' . esc_attr( $cls ) . '"><div class="nbox">' . $this->icon( $icon ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- icon is static SVG.
		echo '<div class="nm">' . esc_html( $name ) . '</div><div class="ds">' . esc_html( $desc ) . '</div></div>';
	}

	protected function render_pipeline( $shield_on, $cf_on, $r ) {
		$affected = empty( $r['php']['is_fixed'] );
		echo '<div class="p2s-card p2s-pipe">';
		$this->card_head( 'zap', 'Defense pipeline' );
		echo '<p class="p2s-dim" style="margin-top:-6px">How an incoming request is handled. Defences act <strong>before PHP runs</strong> &mdash; the only place this exploit can be stopped.</p>';
		echo '<div class="p2s-track' . ( $shield_on ? ' live' : '' ) . '">';
		echo '<span class="trackline"></span><span class="pkt"></span>';
		$this->pipe_node( 'globe', 'Request', 'from the internet', false );
		$this->pipe_node( 'cloud', 'Cloudflare', $cf_on ? 'edge rule active' : 'optional', $cf_on );
		$this->pipe_node( 'shield', 'Shield', $shield_on ? 'active · before PHP' : 'off', $shield_on, true );
		$this->pipe_node( 'code', 'PHP', $r['php']['version'] . ( $affected ? ' · vulnerable' : ' · patched' ), ! $affected );
		$this->pipe_node( 'wp', 'WordPress', 'your site', false );
		echo '</div>';
		if ( $shield_on ) {
			echo '<div class="p2s-pipecap ok"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg> Upload-style attack requests are inspected and <strong>stopped at the Shield</strong>, before they reach PHP.</div>';
		} else {
			echo '<div class="p2s-pipecap warn"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg> Protection is off &mdash; turn it on below so requests are filtered before PHP runs.</div>';
		}
		echo '</div>';
	}

	protected function post_form( $action, $nonce, $label, $style, $extra_html = '' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin:0 8px 8px 0">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
		wp_nonce_field( $nonce );
		echo $extra_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- caller pre-escapes.
		submit_button( $label, $style, 'submit', false );
		echo '</form>';
	}

	protected function render_control( $shield, $v ) {
		echo '<div class="p2s-card p2s-primary">';
		$this->card_head( 'shield', 'Protection' );

		if ( $shield->is_active() ) {
			if ( 'live' === $v['phase'] ) {
				echo '<p class="p2s-verify p2s-ok-text">&#10003; Protection is on and <strong>verified live</strong> — the settings are in effect right now.</p>';
			} elseif ( 'pending' === $v['phase'] ) {
				echo '<p class="p2s-verify p2s-warn-text">&#9203; Protection is written. PHP caches settings, so it should take effect within about ' . esc_html( (string) $v['remaining'] ) . ' seconds. Re-scan after that to confirm.</p>';
			} else {
				echo '<p class="p2s-verify p2s-bad-text">&#9888; Protection is written, but PHP is <strong>not applying it</strong>. Your host may lock these settings. Apply the manual snippet at host level, or contact your host.</p>';
			}
			$this->post_form( 'p2s_disable', 'p2s_disable', 'Turn off protection', 'secondary' );
			echo '<p class="p2s-dim">Turning it off restores your original configuration exactly.</p>';

		} elseif ( $shield->can_autowrite() ) {
			echo '<p>One click applies PHP\'s recommended safety settings using <code>' . esc_html( $shield->target() ) . '</code>. The plugin keeps a backup, and you can undo it any time.</p>';
			if ( 'htaccess' === $shield->method() ) {
				echo '<p class="p2s-dim">Directives are wrapped in <code>IfModule</code> guards, so they cannot take your site down even if something is unusual about the server.</p>';
			}
			echo '<p class="p2s-honest-inline"><strong>Heads up:</strong> one setting is <code>memory_limit = -1</code> (unlimited). It is PHP\'s own recommendation for this bug, but on a tiny server one runaway script could use a lot of memory. You can undo it any time.</p>';
			$this->post_form( 'p2s_enable', 'p2s_enable', 'Turn on protection', 'primary' );

		} else {
			echo '<p>On this server the plugin cannot write the settings itself. Copy the manual snippet below and apply it (or ask your host to). Then re-scan and the status will update.</p>';
		}

		echo '</div>';
	}

	protected function render_edge( $edge, $r ) {
		echo '<div class="p2s-card">';
		$this->card_head( 'zap', 'Edge request filter', $this->pill( 'warn', 'advanced' ) );
		echo '<p>Blocks file-upload-style requests (multipart POST) except on the paths you allow — PHP\'s suggested front-end control for the upload bug. Extra defence on top of the main protection.</p>';
		echo '<p class="p2s-honest-inline"><strong>This can affect front-end forms and uploads.</strong> Turn it on, then test your contact forms, media uploads and checkout. If something breaks, add its path below or turn it off.</p>';

		if ( $edge->is_active() ) {
			echo '<p class="p2s-verify p2s-ok-text">&#10003; Edge filter is <strong>on</strong> (written to .htaccess).</p>';
			$this->post_form( 'p2s_edge_disable', 'p2s_edge', 'Turn off the filter', 'secondary' );
		} elseif ( $edge->can_write_htaccess() ) {
			$this->post_form( 'p2s_edge_enable', 'p2s_edge', 'Turn on the filter', 'primary' );
		} else {
			echo '<p class="p2s-dim">On this server (' . esc_html( $r['server']['label'] ) . ') the plugin cannot write the filter. Use the nginx snippet below, or the Cloudflare option.</p>';
		}

		$allow = implode( "\n", $edge->allowlist() );
		echo '<h3>Allowlist (paths that may receive uploads)</h3>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="p2s_edge_allow" />';
		wp_nonce_field( 'p2s_edge_allow' );
		echo '<textarea name="allow" rows="5" class="p2s-input" style="max-width:520px">' . esc_textarea( $allow ) . '</textarea><br>';
		submit_button( 'Save allowlist', 'secondary', 'submit', false );
		echo '</form>';

		echo '<h3>nginx snippet</h3>';
		$this->snippet_box( $edge->nginx_snippet() );
		echo '</div>';
	}

	protected function render_cloudflare( $r ) {
		$cfg       = function_exists( 'p2s_cf_config' ) ? p2s_cf_config() : array();
		$connected = ! empty( $cfg['connected'] );
		echo '<div class="p2s-card">';
		$this->card_head( 'cloud', 'Cloudflare edge rule' );

		if ( ! empty( $r['proxy']['cloudflare'] ) ) {
			echo '<p class="p2s-verify p2s-ok-text">&#10003; This site appears to be behind Cloudflare — the strongest place to block the bad request, before it reaches your server.</p>';
		} else {
			echo '<p class="p2s-dim">We did not detect Cloudflare in front of this site. If you do use it, you can still connect below.</p>';
		}

		if ( ! $connected ) {
			echo '<p>Paste a Cloudflare API token with <strong>Zone &rsaquo; WAF &rsaquo; Edit</strong> permission. The plugin finds your zone automatically and can push the filter rule to the edge.</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="p2s_cf_connect" />';
			wp_nonce_field( 'p2s_cf' );
			echo '<input type="password" name="cf_token" class="p2s-input" autocomplete="off" placeholder="Cloudflare API token" style="max-width:360px" /> ';
			submit_button( 'Connect', 'primary', 'submit', false );
			echo '</form>';
			echo '<p class="p2s-dim">The token is stored obfuscated and used only from your server. It is never shown again.</p>';
		} else {
			echo '<p>Connected to the zone for <code>' . esc_html( isset( $cfg['domain'] ) ? $cfg['domain'] : '' ) . '</code>.</p>';
			if ( ! empty( $cfg['rule_on'] ) ) {
				echo '<p class="p2s-verify p2s-ok-text">&#10003; The edge filter rule is deployed at Cloudflare.</p>';
				$this->post_form( 'p2s_cf_remove', 'p2s_cf', 'Remove edge rule', 'secondary' );
			} else {
				$this->post_form( 'p2s_cf_deploy', 'p2s_cf', 'Deploy edge rule', 'primary' );
			}
			$this->post_form( 'p2s_cf_disconnect', 'p2s_cf', 'Disconnect', 'secondary' );
			echo '<p class="p2s-dim">Deploying adds one rule tagged "PHP2Shell Shield". Your other Cloudflare rules are left untouched.</p>';
		}
		echo '</div>';
	}

	protected function render_lockdown( $lock, $r ) {
		echo '<div class="p2s-card p2s-danger-card">';
		$this->card_head( 'lock', 'Lockdown', $this->pill( 'bad', 'emergency' ) );
		echo '<p>The panic button. Takes the site offline for everyone except your IP, and shows a maintenance page. Because it blocks at the web server before PHP runs, it genuinely stops the exploit while you patch. Instantly reversible.</p>';

		if ( ! empty( $r['proxy']['cloudflare'] ) ) {
			echo '<p class="p2s-honest-inline"><strong>You are behind Cloudflare.</strong> Server-level IP rules see Cloudflare\'s IPs, not yours, so this .htaccess lockdown may not reliably let you in. Prefer a Cloudflare-side block, or Cloudflare\'s "Under Attack" mode, while behind Cloudflare.</p>';
		}

		if ( $lock->is_active() ) {
			$ips = implode( ', ', $lock->allowed_ips() );
			echo '<p class="p2s-verify p2s-bad-text">&#128274; Lockdown is <strong>ON</strong>. Allowed: ' . esc_html( $ips ) . '</p>';
			$this->post_form( 'p2s_lock_disable', 'p2s_lock', 'Turn the site back online', 'primary' );
		} else {
			$your_ip = p2s_remote_addr();
			echo '<p>Your current IP is <code>' . esc_html( $your_ip ) . '</code>; it will be allowed in. Add another IP if you need one.</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" onsubmit="return confirm(\'This takes your site offline for everyone except your IP. Continue?\');">';
			echo '<input type="hidden" name="action" value="p2s_lock_enable" />';
			wp_nonce_field( 'p2s_lock' );
			echo '<input type="text" name="extra_ip" class="p2s-input" placeholder="Extra IP (optional)" style="max-width:220px" /> ';
			submit_button( 'Take the site offline', 'delete', 'submit', false );
			echo '</form>';
		}
		echo '</div>';
	}

	protected function render_keys() {
		$keys    = new P2S_Keys();
		$present = $keys->detect();
		echo '<div class="p2s-card">';
		$this->card_head( 'key', 'Remote access keys' );
		echo '<p>These connectors are a master key to your whole site — whoever holds the key can install plugins and run code. In October 2026, stolen UpdraftCentral keys were used to plant backdoors. Cut any you do not recognise or need.</p>';
		if ( empty( $present ) ) {
			echo '<p class="p2s-verify p2s-ok-text">&#10003; No remote-management connectors detected.</p></div>';
			return;
		}
		echo '<table class="widefat striped p2s-table"><tbody>';
		foreach ( $present as $c ) {
			$btn = '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline" onsubmit="return confirm(\'Deactivate this remote connection?\');">'
				. '<input type="hidden" name="action" value="p2s_key_deactivate" />'
				. '<input type="hidden" name="key_id" value="' . esc_attr( $c['id'] ) . '" />'
				. wp_nonce_field( 'p2s_keys', '_wpnonce', true, false )
				. get_submit_button( 'Deactivate', 'secondary small', 'submit', false )
				. '</form>';
			echo '<tr><th scope="row">' . esc_html( $c['name'] ) . '</th><td>' . $btn . '<p class="p2s-dim" style="margin:6px 0 0">' . wp_kses( $c['revoke'], array() ) . '</p></td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- composed above.
		}
		echo '</tbody></table>';
		echo '<p class="p2s-dim">Deactivating is reversible — it switches the connector plugin off, which severs remote control immediately.</p></div>';
	}

	protected function render_scan() {
		$res = p2s_opt_get( 'p2s_scan_result' );
		echo '<div class="p2s-card">';
		$this->card_head( 'search', 'Breach check' );
		echo '<p>PHP2Shell runs as your web user, and attacks started before the patch — so some sites are already compromised. This checks the common signs. It only reports; it never deletes anything.</p>';

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="p2s_scan_run" />';
		wp_nonce_field( 'p2s_scan' );
		submit_button( is_array( $res ) ? 'Run scan again' : 'Run scan', 'primary', 'submit', false );
		echo '</form>';
		echo '<p class="p2s-dim">A scan checks files against WordPress.org and can take a little while on large sites.</p>';

		if ( ! is_array( $res ) ) {
			echo '</div>';
			return;
		}

		echo '<p class="p2s-dim">Last scan: ' . esc_html( gmdate( 'Y-m-d H:i', $res['time'] ) ) . ' UTC</p>';
		$clean = true;

		if ( is_array( $res['core'] ) && ! empty( $res['core']['ok'] ) ) {
			$mod = array_merge( $res['core']['modified'], $res['core']['missing'] );
			if ( ! empty( $mod ) ) {
				$clean = false;
				$this->finding( 'bad', 'Core files differ from WordPress.org', $mod );
			}
		} elseif ( is_array( $res['core'] ) ) {
			echo '<p class="p2s-dim">Core checksums could not be fetched this run.</p>';
		}

		if ( ! empty( $res['plugins'] ) ) {
			foreach ( $res['plugins'] as $p ) {
				if ( ! empty( $p['verifiable'] ) ) {
					$mod = array_merge( isset( $p['modified'] ) ? $p['modified'] : array(), isset( $p['missing'] ) ? $p['missing'] : array() );
					if ( ! empty( $mod ) ) {
						$clean = false;
						$this->finding( 'bad', 'Plugin "' . $p['slug'] . '" files differ from WordPress.org', $mod );
					}
				}
			}
		}

		if ( ! empty( $res['uploads'] ) ) {
			$clean = false;
			$this->finding( 'bad', 'PHP files found in uploads (should never happen)', $res['uploads'] );
		}

		if ( ! empty( $res['admins'] ) ) {
			$clean = false;
			$list  = array();
			foreach ( $res['admins'] as $a ) {
				$list[] = $a['login'] . ' (' . $a['registered'] . ')';
			}
			$this->finding( 'warn', 'Admin accounts created in the last 30 days — confirm you made these', $list );
		}

		if ( $clean ) {
			echo '<p class="p2s-verify p2s-ok-text">&#10003; No signs of compromise found. (A clean scan is reassuring, not a guarantee.)</p>';
		}
		echo '</div>';
	}

	protected function finding( $tone, $title, $items ) {
		echo '<div class="p2s-finding p2s-' . esc_attr( $tone ) . '-text"><strong>' . esc_html( $title ) . '</strong><ul class="p2s-notes">';
		$shown = 0;
		foreach ( $items as $it ) {
			echo '<li>' . esc_html( $it ) . '</li>';
			if ( ++$shown >= 50 ) {
				echo '<li>&hellip; and more</li>';
				break;
			}
		}
		echo '</ul></div>';
	}

	protected function render_secrets() {
		$secrets = new P2S_Secrets();
		echo '<div class="p2s-card">';
		$this->card_head( 'refresh', 'Secrets reset' );
		echo '<p>PHP2Shell can leak memory that held passwords and keys. Rotating your WordPress security keys makes any stolen login session useless and signs everyone out.</p>';
		echo '<p class="p2s-honest-inline"><strong>This signs out every user, including you.</strong> You will need to log in again straight after. Your original wp-config.php is backed up first.</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" onsubmit="return confirm(\'Rotate security keys now? Everyone will be signed out.\');">';
		echo '<input type="hidden" name="action" value="p2s_secrets_rotate" />';
		wp_nonce_field( 'p2s_secrets' );
		submit_button( 'Rotate security keys', 'primary', 'submit', false );
		echo '</form>';

		echo '<h3>Also change these yourself</h3>';
		echo '<p class="p2s-dim">The plugin cannot rotate these for you. If you think you were breached, change each one:</p>';
		echo '<ul class="p2s-notes">';
		foreach ( $secrets->checklist() as $item ) {
			echo '<li>' . esc_html( $item ) . '</li>';
		}
		echo '</ul></div>';
	}

	protected function render_pack( $engine ) {
		$s = $engine->summary( 'php2shell' );
		echo '<div class="p2s-card">';
		$this->card_head( 'file', 'Threat definitions' );

		if ( empty( $s['loaded'] ) ) {
			if ( empty( $s['can_verify'] ) ) {
				echo '<p class="p2s-bad-text">&#9888; The rule pack could not be verified on this server (the OpenSSL extension is missing), so signed pack updates are unavailable. The plugin is using its built-in defaults.</p>';
			} else {
				echo '<p class="p2s-bad-text">&#9888; No valid rule pack is loaded. The plugin is using its built-in defaults.</p>';
			}
			echo '</div>';
			return;
		}

		$cves = is_array( $s['cve'] ) ? implode( ', ', $s['cve'] ) : '';
		echo '<table class="widefat striped p2s-table"><tbody>';
		$this->row( 'Threat', esc_html( $s['name'] ) . $this->pill( 'bad', $s['severity'] ) );
		$this->row( 'CVEs', esc_html( $cves ) );
		$this->row( 'Definition version', esc_html( $s['pack_version'] ) . ' <span class="p2s-dim">(' . esc_html( $s['updated'] ) . ')</span>' );
		$this->row( 'Source', esc_html( ucfirst( $s['source'] ) ) . ' &middot; Signature verified' . $this->pill( 'ok', 'trusted' ) );
		echo '</tbody></table>';
		echo '<p class="p2s-dim">Rule packs are cryptographically signed. The plugin refuses any pack that is unsigned or has been tampered with.</p>';
		echo '</div>';
	}

	protected function render_environment( $r ) {
		echo '<div class="p2s-card">';
		$this->card_head( 'server', 'Your environment' );
		echo '<table class="widefat striped p2s-table"><tbody>';

		$php_val  = esc_html( $r['php']['version'] ) . ' &middot; ' . esc_html( $r['php']['sapi_label'] );
		$php_val .= $r['php']['is_fixed'] ? $this->pill( 'ok', 'fixed version' ) : $this->pill( 'bad', 'affected' );
		$this->row( 'PHP', $php_val );
		$this->row( 'Web server', esc_html( $r['server']['label'] ) . ' <span class="p2s-dim">(' . esc_html( $r['server']['software'] ) . ')</span>' );
		$this->row( 'In front of the site', esc_html( $r['proxy']['label'] ) );
		$this->row( 'Protection method here', esc_html( $r['shield']['method_label'] ) );

		$mem = $r['mitigations']['memory_limit'];
		$up  = $r['mitigations']['upload_progress'];
		$this->row( 'memory_limit', esc_html( $mem['current'] ) . ' &rarr; target ' . esc_html( $mem['target'] ) . ' ' . $this->tick( $mem['ok'] ) );
		$this->row( 'session.upload_progress', esc_html( $up['current'] ) . ' &rarr; target ' . esc_html( $up['target'] ) . ' ' . $this->tick( $up['ok'] ) );

		echo '</tbody></table>';

		echo '<form method="get" class="p2s-rescan"><input type="hidden" name="page" value="' . esc_attr( P2S_SLUG ) . '" />';
		submit_button( 'Re-scan', 'secondary', 'p2s_rescan', false );
		echo '</form></div>';
	}

	protected function render_snippet( $shield ) {
		echo '<div class="p2s-card">';
		$this->card_head( 'file', 'Manual snippet' );
		echo '<p class="p2s-dim">For your host, or if you prefer to apply it yourself (for example at PHP-FPM pool level, which survives everything). Click the box to select all, then copy.</p>';
		$this->snippet_box( $shield->snippet() );
		echo '</div>';
	}

	protected function row( $label, $value_html ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . $value_html . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- value pre-escaped by caller.
	}

	protected function tick( $ok ) {
		return $ok ? $this->pill( 'ok', 'on' ) : $this->pill( 'bad', 'not set' );
	}

	protected function css() {
		return '
		.p2s-wrap{max-width:1080px;margin:10px 20px 0 2px;--g:#1a7f37;--g2:#22a04a;--gl:#45c46e;--mint:#eaf8f0;--ink:#0f1b24;--muted:#5e6e76;--dim:#8a98a0;--line:#e5ebf0;--card:#ffffff}
		.p2s-wrap *{box-sizing:border-box}
		.p2s-wrap h1,.p2s-wrap h2,.p2s-wrap h3{color:var(--ink)}

		/* ---- hero core ---- */
		.p2s-core{position:relative;overflow:hidden;display:grid;grid-template-columns:230px 1fr;gap:26px;align-items:center;
			background:linear-gradient(135deg,#ffffff 0%,#f2fbf6 55%,#eef7ff 100%);
			border:1px solid #d9eadf;border-radius:22px;padding:26px 30px;margin:16px 0 14px;
			box-shadow:0 1px 2px rgba(16,40,30,.04),0 24px 60px rgba(16,60,40,.08)}
		.p2s-core::after{content:"";position:absolute;right:-80px;top:-80px;width:280px;height:280px;border-radius:50%;
			background:radial-gradient(circle,rgba(34,160,74,.10),transparent 70%);pointer-events:none}
		.p2s-reactor{position:relative;width:200px;height:200px;margin:auto}
		.p2s-reactor .rr{position:absolute;border-radius:50%;border:1px solid rgba(26,127,55,.18)}
		.p2s-reactor .r1{inset:2px;border-style:dashed;animation:p2sspin 28s linear infinite}
		.p2s-reactor .r2{inset:30px;border-color:rgba(10,150,170,.18);animation:p2sspin 20s linear infinite reverse}
		.p2s-reactor .r3{inset:58px;border-style:dashed;border-color:rgba(26,127,55,.28);animation:p2sspin 13s linear infinite}
		.p2s-reactor .sweep{position:absolute;inset:2px;border-radius:50%;background:conic-gradient(from 0deg,rgba(34,160,74,0) 300deg,rgba(34,160,74,.18) 360deg);
			-webkit-mask:radial-gradient(circle,transparent 54%,#000 55%);mask:radial-gradient(circle,transparent 54%,#000 55%);animation:p2sspin 5s linear infinite}
		.p2s-reactor .score{position:absolute;inset:0;display:grid;place-items:center}
		.p2s-reactor .score .p2s-logo{width:76px;height:76px;filter:drop-shadow(0 6px 14px rgba(26,127,55,.28))}
		@keyframes p2sspin{to{transform:rotate(360deg)}}
		.p2s-core-read .p2s-eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--g);background:var(--mint);border:1px solid #cfeada;padding:5px 12px;border-radius:999px}
		.p2s-core-read .p2s-eyebrow .pulse{width:7px;height:7px;border-radius:50%;background:var(--g2);box-shadow:0 0 0 0 rgba(34,160,74,.5);animation:p2spulse 2.2s infinite}
		@keyframes p2spulse{0%{box-shadow:0 0 0 0 rgba(34,160,74,.45)}70%{box-shadow:0 0 0 8px rgba(34,160,74,0)}100%{box-shadow:0 0 0 0 rgba(34,160,74,0)}}
		.p2s-word{font-size:46px;line-height:1.02;font-weight:800;letter-spacing:-.5px;margin:12px 0 8px;
			background:linear-gradient(90deg,#16a34a,#1a7f37 55%,#0aa5c9);-webkit-background-clip:text;background-clip:text;color:transparent}
		.p2s-core.p2s-warn .p2s-word{background:linear-gradient(90deg,#d08700,#b45309);-webkit-background-clip:text;background-clip:text}
		.p2s-core.p2s-bad .p2s-word{background:linear-gradient(90deg,#e5484d,#b42318);-webkit-background-clip:text;background-clip:text}
		.p2s-core-read>p{font-size:14.5px;line-height:1.6;color:#3c4a52;max-width:560px;margin:0 0 14px}
		.p2s-layers{max-width:420px;margin:4px 0 14px}
		.p2s-layers .bar{height:9px;border-radius:999px;background:#e6edf1;overflow:hidden}
		.p2s-layers .bar i{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--g),var(--gl));box-shadow:0 0 10px rgba(34,160,74,.4);transition:width .6s}
		.p2s-layers .llbl{display:flex;justify-content:space-between;font-size:11px;font-weight:600;letter-spacing:.4px;color:var(--muted);margin-top:6px}
		.p2s-chips{display:flex;flex-wrap:wrap;gap:8px}
		.p2s-chips .pc{font-size:12px;color:var(--muted);background:#f3f6f8;border:1px solid var(--line);border-radius:999px;padding:5px 12px}
		.p2s-chips .pc b{margin-left:4px;font-size:10px;padding:1px 7px;border-radius:999px}
		.p2s-chips .pc b.ok{background:#e6f4ea;color:#15803d}.p2s-chips .pc b.bad{background:#fde8e6;color:#b42318}
		@media(max-width:820px){.p2s-core{grid-template-columns:1fr;text-align:center}.p2s-layers,.p2s-core-read>p{margin-left:auto;margin-right:auto}.p2s-chips{justify-content:center}.p2s-word{font-size:36px}}

		/* ---- pipeline ---- */
		.p2s-track{position:relative;display:flex;align-items:flex-start;justify-content:space-between;margin:16px 0 4px;padding:0 6px}
		.p2s-track .trackline{position:absolute;left:8%;right:8%;top:34px;height:3px;border-radius:3px;background:linear-gradient(90deg,#0aa5c9,#22a04a 55%,#f2b705);opacity:.55}
		.p2s-track .pkt{position:absolute;left:8%;top:34px;width:11px;height:11px;border-radius:50%;background:#e5484d;box-shadow:0 0 0 4px rgba(229,72,77,.18);transform:translate(-50%,-50%);opacity:0}
		.p2s-track.live .pkt{opacity:1;animation:p2sflow 4.4s cubic-bezier(.5,0,.5,1) infinite}
		@keyframes p2sflow{0%{left:8%;background:#e5484d}42%{left:46%;background:#e5484d}
			50%{left:47%;transform:translate(-50%,-50%) scale(1.9);background:#22a04a;box-shadow:0 0 0 6px rgba(34,160,74,.25)}
			58%,100%{left:47%;opacity:0;transform:translate(-50%,-50%) scale(.3)}}
		.p2s-node{position:relative;z-index:2;text-align:center;width:118px}
		.p2s-node .nbox{width:68px;height:68px;margin:0 auto 10px;border-radius:18px;display:grid;place-items:center;background:#fff;border:1px solid var(--line);color:var(--dim);box-shadow:0 6px 16px rgba(16,40,30,.06)}
		.p2s-node .nbox .p2s-ic{background:none;width:auto;height:auto}.p2s-node .nbox svg{width:26px;height:26px}
		.p2s-node.on .nbox{color:var(--g);border-color:#bfe3c9;background:var(--mint)}
		.p2s-node.guard .nbox{color:#fff;border-color:transparent;background:linear-gradient(135deg,#1a7f37,#22a04a);box-shadow:0 10px 24px rgba(26,127,55,.35);animation:p2sguard 3s ease-in-out infinite}
		.p2s-node.guard:not(.on) .nbox{background:#fff;color:var(--dim);box-shadow:0 6px 16px rgba(16,40,30,.06);animation:none}
		@keyframes p2sguard{0%,100%{box-shadow:0 8px 20px rgba(26,127,55,.28)}50%{box-shadow:0 10px 30px rgba(26,127,55,.5)}}
		.p2s-node .nm{font-size:12.5px;font-weight:700;letter-spacing:.4px;color:var(--ink)}
		.p2s-node.guard .nm{color:var(--g)}
		.p2s-node .ds{font-size:10.5px;color:var(--dim);margin-top:3px;font-family:ui-monospace,Menlo,Consolas,monospace}
		.p2s-pipecap{display:flex;gap:9px;align-items:center;margin-top:16px;font-size:13.5px;padding:11px 15px;border-radius:12px}
		.p2s-pipecap.ok{background:#eefaf1;border:1px solid #cdecd6;color:#15803d}
		.p2s-pipecap.warn{background:#fff8e6;border:1px solid #f0d58a;color:#92600a}
		.p2s-pipecap svg{flex:0 0 auto}
		@media(max-width:700px){.p2s-track{flex-wrap:wrap;gap:14px;justify-content:center}.p2s-track .trackline,.p2s-track .pkt{display:none}}
		/* hero */
		.p2s-hero{display:flex;align-items:center;gap:20px;background:linear-gradient(135deg,#0b0f10 0%,#101f24 60%,#0b0f10 100%);color:#fff;border-radius:18px;padding:26px 30px;margin:18px 0 22px;box-shadow:0 10px 30px rgba(0,0,0,.18)}
		.p2s-hero-logo{width:64px;height:64px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;background:rgba(63,185,80,.12);border:1px solid rgba(63,185,80,.35);border-radius:16px}
		.p2s-logo{width:38px;height:38px}
		.p2s-hero-text h1{color:#fff;margin:0;font-size:26px;font-weight:800;letter-spacing:-.3px}
		.p2s-hero-text p{color:#9aa7ad;margin:4px 0 0;font-size:15px}
		.p2s-badge{margin-left:auto;font-weight:700;padding:8px 18px;border-radius:999px;font-size:13px;letter-spacing:.3px}
		/* group dividers */
		.p2s-group{margin:30px 0 6px;font-size:12px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:#8a9096;border-bottom:1px solid #e3e6ea;padding-bottom:8px}
		/* cards */
		.p2s-card{background:#fff;border:1px solid #e3e6ea;border-radius:16px;padding:22px 24px;margin:14px 0;box-shadow:0 1px 2px rgba(0,0,0,.04),0 6px 18px rgba(0,0,0,.03)}
		.p2s-card p{font-size:14.5px;line-height:1.6;color:#3c434a}
		.p2s-card code{background:#f3f5f7;border-radius:5px;padding:1px 6px;font-size:12.5px;color:#0b0f10}
		.p2s-head{display:flex;align-items:center;gap:11px;margin:0 0 12px}
		.p2s-head h2{margin:0;font-size:18px;font-weight:700;color:#11181c}
		.p2s-ic{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:10px;background:#eef6ef;color:#1a7f37;flex:0 0 auto}
		.p2s-ic svg{width:19px;height:19px}
		.p2s-card h3{font-size:14px;font-weight:700;color:#11181c;margin:18px 0 8px}
		/* primary card */
		.p2s-primary{border:1px solid #bfe3c6;background:linear-gradient(180deg,#f3fbf5 0%,#ffffff 70%)}
		.p2s-primary .p2s-ic{background:#1a7f37;color:#fff}
		.p2s-danger-card{border-color:#f3c6c3}
		.p2s-danger-card .p2s-ic{background:#fdecea;color:#c5221f}
		/* status */
		.p2s-status{display:flex;gap:18px;align-items:flex-start;border-left-width:5px;border-left-style:solid}
		.p2s-status-body h2{margin:0 0 4px;font-size:22px;font-weight:800;color:#11181c}
		.p2s-light{width:22px;height:22px;border-radius:50%;margin-top:6px;flex:0 0 auto}
		.p2s-notes{margin:10px 0 0;padding-left:20px;color:#5a626a}
		.p2s-notes li{margin:3px 0;font-size:13.5px}
		/* honesty / inline note */
		.p2s-honest{background:#fff8e6;border:1px solid #f0d58a;border-left:4px solid #dba617;border-radius:12px;padding:14px 18px;margin:14px 0;color:#5a4a16;font-size:14px}
		.p2s-honest-inline{background:#fff8e6;border:1px solid #f0d58a;border-radius:10px;padding:11px 15px;color:#5a4a16;font-size:13.5px}
		/* verify lines */
		.p2s-verify{font-size:14.5px;padding:12px 16px;border-radius:10px;background:#f4f6f8;margin:12px 0}
		.p2s-ok-text{color:#15803d}.p2s-warn-text{color:#92600a}.p2s-bad-text{color:#b42318}
		.p2s-finding{border-left:4px solid currentColor;padding:10px 16px;margin:12px 0;background:#f7f8fa;border-radius:0 10px 10px 0}
		.p2s-finding ul{color:#5a626a}
		/* table */
		.p2s-table{border-radius:10px;overflow:hidden;border:1px solid #e3e6ea;margin-top:6px}
		.p2s-table th{width:230px;font-size:13.5px}
		.p2s-table td{font-size:13.5px}
		/* pills & dim */
		.p2s-pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px;vertical-align:middle;letter-spacing:.2px}
		.p2s-dim{color:#8a9096;font-size:13px}
		.p2s-rescan{margin-top:14px}
		.p2s-input{width:100%;max-width:520px;border:1px solid #cfd4da;border-radius:9px;padding:9px 12px;font-size:13.5px}
		.p2s-foot{text-align:center;color:#9aa0a6;font-size:12.5px;margin:26px 0 8px}
		.p2s-foot a{color:#1a7f37;text-decoration:none}
		/* how it works */
		.p2s-how{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:10px 0 4px}
		.p2s-step{background:#fff;border:1px solid #e3e6ea;border-radius:16px;padding:20px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
		.p2s-step-ic{width:46px;height:46px;border-radius:13px;background:linear-gradient(135deg,#1a7f37,#2ea44f);color:#fff;display:flex;align-items:center;justify-content:center;margin-bottom:12px}
		.p2s-step-ic .p2s-ic{width:auto;height:auto;background:none;color:#fff}
		.p2s-step-ic svg{width:23px;height:23px}
		.p2s-step h3{margin:0 0 6px;font-size:15px;font-weight:700;color:#11181c}
		.p2s-step p{margin:0;font-size:13.5px;line-height:1.55;color:#5a626a}
		@media (max-width:860px){.p2s-how{grid-template-columns:1fr}}
		/* tones */
		.p2s-ok{background:#e6f4ea;color:#15803d}
		.p2s-warn{background:#fef4e2;color:#92600a}
		.p2s-bad{background:#fde8e6;color:#b42318}
		.p2s-badge.p2s-ok{background:#1e8e3e;color:#fff}
		.p2s-badge.p2s-warn{background:#f29900;color:#1b1b1b}
		.p2s-badge.p2s-bad{background:#e5484d;color:#fff}
		.p2s-status.p2s-ok{border-left-color:#1e8e3e}.p2s-status.p2s-ok .p2s-light{background:#1e8e3e}
		.p2s-status.p2s-warn{border-left-color:#f29900}.p2s-status.p2s-warn .p2s-light{background:#f29900}
		.p2s-status.p2s-bad{border-left-color:#e5484d}.p2s-status.p2s-bad .p2s-light{background:#e5484d}
		/* buttons */
		.p2s-wrap .button{border-radius:8px;font-weight:600;padding:4px 16px;height:auto;line-height:2.1}
		.p2s-wrap .button-primary{background:#1a7f37;border-color:#166e30;box-shadow:none;text-shadow:none}
		.p2s-wrap .button-primary:hover,.p2s-wrap .button-primary:focus{background:#15803d;border-color:#135c2b}
		.p2s-wrap .button.delete,.p2s-wrap .button-link-delete{background:#e5484d;border:1px solid #c5221f;color:#fff;border-radius:8px;padding:4px 16px;font-weight:600;text-decoration:none}
		.p2s-wrap .button.delete:hover,.p2s-wrap .button-link-delete:hover{background:#c5221f;color:#fff}
		';
	}
}
