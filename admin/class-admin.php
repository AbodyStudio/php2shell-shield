<?php
/**
 * Admin UI for PHP2Shell Shield.
 *
 * M0: read-only detection dashboard.
 * M1: one-click shield (enable / disable), verification, and a manual snippet.
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
			'dashicons-shield',
			81
		);
	}

	public function assets( $hook ) {
		if ( 'toplevel_page_' . P2S_SLUG !== $hook ) {
			return;
		}
		wp_add_inline_style( 'wp-admin', $this->css() );
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
		// If the filter is live, re-write it with the new allowlist.
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
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
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
			$c             = p2s_cf_config();
			$c['rule_on']  = 1;
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
		// Rotating salts invalidates our own cookie, so the redirect may land on
		// the login screen — that is expected and fine.
		$this->back( ! empty( $res['ok'] ) ? 'secrets_done' : 'secrets_fail' );
	}

	/* ---- notices ------------------------------------------------------- */

	protected function notice() {
		if ( ! isset( $_GET['p2s_notice'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$n = sanitize_text_field( wp_unslash( $_GET['p2s_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( 'enabled' === $n ) {
			$this->admin_box( 'success', 'Shield turned on. The settings were written. PHP may take a few minutes to pick them up on some servers — re-scan to confirm.' );
		} elseif ( 'disabled' === $n ) {
			$this->admin_box( 'info', 'Shield turned off. Your original configuration was restored.' );
		} elseif ( 'enable_failed_not_writable' === $n ) {
			$this->admin_box( 'error', 'The plugin could not write the config file (the server blocked it). Use the manual snippet below, or ask your host to apply it.' );
		} elseif ( 'enable_failed_snippet_only' === $n ) {
			$this->admin_box( 'error', 'This server type needs a host-side change. Use the manual snippet below.' );
		} elseif ( 0 === strpos( $n, 'enable_failed' ) ) {
			$this->admin_box( 'error', 'The shield could not be turned on automatically. Use the manual snippet below.' );
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

	/* ---- status tone --------------------------------------------------- */

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
		$tone   = $this->tone( $r['status']['code'] );

		echo '<div class="wrap p2s-wrap">';

		/* Hero */
		echo '<div class="p2s-hero">';
		echo '<div class="p2s-hero-mark">&#128737;</div>';
		echo '<div class="p2s-hero-text"><h1>PHP2Shell Shield</h1><p>Block the exploit. Protect your site.</p></div>';
		echo '<div class="p2s-badge p2s-' . esc_attr( $tone ) . '">' . esc_html( $r['status']['label'] ) . '</div>';
		echo '</div>';

		$this->notice();

		/* Status card */
		echo '<div class="p2s-card p2s-status p2s-' . esc_attr( $tone ) . '">';
		echo '<div class="p2s-light"></div>';
		echo '<div class="p2s-status-body">';
		echo '<h2>' . esc_html( $r['status']['label'] ) . '</h2>';
		echo '<p>' . esc_html( $r['status']['summary'] ) . '</p>';
		if ( ! empty( $r['status']['notes'] ) ) {
			echo '<ul class="p2s-notes">';
			foreach ( $r['status']['notes'] as $note ) {
				echo '<li>' . esc_html( $note ) . '</li>';
			}
			echo '</ul>';
		}
		echo '</div></div>';

		/* Honesty banner */
		echo '<div class="p2s-honest"><strong>This is risk reduction, not a true fix.</strong> ';
		echo 'The only real fix for PHP2Shell is updating PHP to a fixed version';
		if ( $r['php']['fixed_version'] ) {
			echo ' (' . esc_html( $r['php']['fixed_version'] ) . ' for your branch)';
		}
		echo '. The shield lowers your risk and tells you if you were already hit. It cannot make an unpatched server perfectly safe.</div>';

		/* The shield control */
		$this->render_control( $shield, $v );

		/* Edge filter + lockdown (M3) */
		$this->render_edge( new P2S_Edge( null, $r ), $r );
		$this->render_cloudflare( $r );
		$this->render_lockdown( new P2S_Lockdown(), $r );

		/* Breach check + remote keys (M4) */
		$this->render_keys();
		$this->render_scan();

		/* Secrets reset (M5) */
		$this->render_secrets();

		/* Environment table */
		$this->render_environment( $r );

		/* Threat definitions (rule pack) */
		$this->render_pack( $engine );

		/* Manual snippet */
		$this->render_snippet( $shield );

		echo '</div>';
	}

	protected function post_form( $action, $nonce, $label, $style, $extra_html = '' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin-right:8px">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
		wp_nonce_field( $nonce );
		echo $extra_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from esc_* below.
		submit_button( $label, $style, 'submit', false );
		echo '</form>';
	}

	protected function render_edge( $edge, $r ) {
		echo '<div class="p2s-card"><h2>Edge request filter <span class="p2s-pill p2s-warn">advanced</span></h2>';
		echo '<p>Blocks file-upload-style requests (multipart POST) except on the paths you allow — this is PHP\'s suggested front-end control for the upload bug. It is extra defence on top of the shield.</p>';
		echo '<p class="p2s-honest-inline"><strong>This can affect front-end forms and uploads.</strong> Turn it on, then test your contact forms, media uploads and checkout. If something breaks, add its path below or turn it off.</p>';

		if ( $edge->is_active() ) {
			echo '<p class="p2s-verify p2s-ok-text">&#10003; Edge filter is <strong>on</strong> (written to .htaccess).</p>';
			$this->post_form( 'p2s_edge_disable', 'p2s_edge', 'Turn off the filter', 'secondary' );
		} elseif ( $edge->can_write_htaccess() ) {
			$this->post_form( 'p2s_edge_enable', 'p2s_edge', 'Turn on the filter', 'primary' );
		} else {
			echo '<p class="p2s-dim">On this server (' . esc_html( $r['server']['label'] ) . ') the plugin cannot write the filter. Use the nginx snippet below, or the Cloudflare option.</p>';
		}

		// Allowlist editor.
		$allow = implode( "\n", $edge->allowlist() );
		echo '<h3 style="margin-top:18px">Allowlist (paths that may receive uploads)</h3>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="p2s_edge_allow" />';
		wp_nonce_field( 'p2s_edge_allow' );
		echo '<textarea name="allow" rows="5" class="large-text code" style="max-width:520px">' . esc_textarea( $allow ) . '</textarea><br>';
		submit_button( 'Save allowlist', 'secondary', 'submit', false );
		echo '</form>';

		echo '<h3 style="margin-top:18px">nginx snippet</h3>';
		echo '<textarea class="p2s-snippet" rows="' . esc_attr( (string) ( substr_count( $edge->nginx_snippet(), "\n" ) + 1 ) ) . '" readonly="readonly" onclick="this.select()">' . esc_textarea( $edge->nginx_snippet() ) . '</textarea>';
		echo '</div>';
	}

	protected function render_cloudflare( $r ) {
		$cfg       = function_exists( 'p2s_cf_config' ) ? p2s_cf_config() : array();
		$connected = ! empty( $cfg['connected'] );
		echo '<div class="p2s-card"><h2>Cloudflare edge rule</h2>';

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
			echo '<input type="password" name="cf_token" class="regular-text" autocomplete="off" placeholder="Cloudflare API token" /> ';
			submit_button( 'Connect', 'primary', 'submit', false );
			echo '</form>';
			echo '<p class="p2s-dim">The token is stored obfuscated and used only from your server. It is never shown again.</p>';
		} else {
			echo '<p>Connected to zone for <code>' . esc_html( isset( $cfg['domain'] ) ? $cfg['domain'] : '' ) . '</code>.</p>';
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
		echo '<div class="p2s-card"><h2>Lockdown <span class="p2s-pill p2s-bad">emergency</span></h2>';
		echo '<p>The panic button. Takes the site offline for everyone except your IP, and shows a maintenance page. Because it blocks at the web server before PHP runs, it genuinely stops the exploit while you patch. Instantly reversible.</p>';

		$behind_cf = ! empty( $r['proxy']['cloudflare'] );
		if ( $behind_cf ) {
			echo '<p class="p2s-honest-inline"><strong>You are behind Cloudflare.</strong> Server-level IP rules see Cloudflare\'s IPs, not yours, so this .htaccess lockdown may not reliably allow you in. Prefer a Cloudflare-side block, or Cloudflare\'s "Under Attack" mode, while behind Cloudflare.</p>';
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
			echo '<input type="text" name="extra_ip" class="regular-text" placeholder="Extra IP (optional)" /> ';
			submit_button( 'Take the site offline', 'delete', 'submit', false );
			echo '</form>';
		}
		echo '</div>';
	}

	protected function render_pack( $engine ) {
		$s = $engine->summary( 'php2shell' );
		echo '<div class="p2s-card"><h2>Threat definitions</h2>';

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
		$this->row( 'Threat', esc_html( $s['name'] ) . ' <span class="p2s-pill p2s-bad">' . esc_html( $s['severity'] ) . '</span>' );
		$this->row( 'CVEs', esc_html( $cves ) );
		$this->row( 'Definition version', esc_html( $s['pack_version'] ) . ' <span class="p2s-dim">(' . esc_html( $s['updated'] ) . ')</span>' );
		$sig_label = 'Signature verified <span class="p2s-pill p2s-ok">trusted</span>';
		$this->row( 'Source', esc_html( ucfirst( $s['source'] ) ) . ' &middot; ' . $sig_label );
		echo '</tbody></table>';
		echo '<p class="p2s-dim">Rule packs are cryptographically signed. The plugin refuses any pack that is unsigned or has been tampered with.</p>';
		echo '</div>';
	}

	protected function render_control( $shield, $v ) {
		echo '<div class="p2s-card">';
		echo '<h2>The shield</h2>';

		if ( $shield->is_active() ) {
			// Verification state.
			if ( 'live' === $v['phase'] ) {
				echo '<p class="p2s-verify p2s-ok-text">&#10003; Shield is on and <strong>verified live</strong> — the settings are in effect right now.</p>';
			} elseif ( 'pending' === $v['phase'] ) {
				echo '<p class="p2s-verify p2s-warn-text">&#9203; Shield is written. PHP caches settings, so it should take effect within about ' . esc_html( (string) $v['remaining'] ) . ' seconds. Re-scan after that to confirm.</p>';
			} else {
				echo '<p class="p2s-verify p2s-bad-text">&#9888; Shield is written, but PHP is <strong>not applying it</strong>. Your host may lock these settings. Apply the snippet below at host level, or contact your host.</p>';
			}

			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="p2s_disable" />';
			wp_nonce_field( 'p2s_disable' );
			submit_button( 'Turn off the shield', 'secondary', 'submit', false );
			echo '</form>';
			echo '<p class="p2s-dim">Turning it off restores your original configuration exactly.</p>';

		} elseif ( $shield->can_autowrite() ) {
			echo '<p>The plugin can turn on the shield for you by writing <code>' . esc_html( $shield->target() ) . '</code>. It keeps a backup, and you can undo it any time.</p>';
			if ( 'htaccess' === $shield->method() ) {
				echo '<p class="p2s-dim">Directives are wrapped in <code>IfModule</code> guards, so they cannot take your site down even if something is unusual about the server.</p>';
			}
			echo '<p class="p2s-honest-inline"><strong>Heads up:</strong> one of the settings is <code>memory_limit = -1</code> (unlimited). It is PHP\'s own recommendation for this bug, but on a tiny server one runaway script could use a lot of memory. You can undo it any time.</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="p2s_enable" />';
			wp_nonce_field( 'p2s_enable' );
			submit_button( 'Turn on the shield', 'primary', 'submit', false );
			echo '</form>';

		} else {
			echo '<p>On this server the plugin cannot write the shield itself. Copy the snippet below and apply it (or ask your host to). After it is in place, re-scan and the status will update.</p>';
		}

		echo '</div>';
	}

	protected function render_keys() {
		$keys    = new P2S_Keys();
		$present = $keys->detect();
		echo '<div class="p2s-card"><h2>Remote access keys</h2>';
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
			echo '<tr><th scope="row">' . esc_html( $c['name'] ) . '</th><td>' . $btn . '<p class="p2s-dim" style="margin:6px 0 0">' . wp_kses( $c['revoke'], array() ) . '</p></td></tr>';
		}
		echo '</tbody></table>';
		echo '<p class="p2s-dim">Deactivating is reversible — it switches the connector plugin off, which severs remote control immediately.</p></div>';
	}

	protected function render_scan() {
		$res = p2s_opt_get( 'p2s_scan_result' );
		echo '<div class="p2s-card"><h2>Breach check</h2>';
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

		// Core.
		if ( is_array( $res['core'] ) && ! empty( $res['core']['ok'] ) ) {
			$mod = array_merge( $res['core']['modified'], $res['core']['missing'] );
			if ( ! empty( $mod ) ) {
				$clean = false;
				$this->finding( 'bad', 'Core files differ from WordPress.org', $mod );
			}
		} elseif ( is_array( $res['core'] ) ) {
			echo '<p class="p2s-dim">Core checksums could not be fetched this run.</p>';
		}

		// Plugins.
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

		// Uploads.
		if ( ! empty( $res['uploads'] ) ) {
			$clean = false;
			$this->finding( 'bad', 'PHP files found in uploads (should never happen)', $res['uploads'] );
		}

		// Recent admins.
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
		echo '<div class="p2s-card"><h2>Secrets reset</h2>';
		echo '<p>PHP2Shell can leak memory that held passwords and keys. Rotating your WordPress security keys makes any stolen login session useless and signs everyone out.</p>';
		echo '<p class="p2s-honest-inline"><strong>This signs out every user, including you.</strong> You will need to log in again straight after. Your original wp-config.php is backed up first.</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" onsubmit="return confirm(\'Rotate security keys now? Everyone will be signed out.\');">';
		echo '<input type="hidden" name="action" value="p2s_secrets_rotate" />';
		wp_nonce_field( 'p2s_secrets' );
		submit_button( 'Rotate security keys', 'primary', 'submit', false );
		echo '</form>';

		echo '<h3 style="margin-top:18px">Also change these yourself</h3>';
		echo '<p class="p2s-dim">The plugin cannot rotate these for you. If you think you were breached, change each one:</p>';
		echo '<ul class="p2s-notes">';
		foreach ( $secrets->checklist() as $item ) {
			echo '<li>' . esc_html( $item ) . '</li>';
		}
		echo '</ul></div>';
	}

	protected function render_environment( $r ) {
		echo '<div class="p2s-card"><h2>Your environment</h2>';
		echo '<table class="widefat striped p2s-table"><tbody>';

		$php_val = esc_html( $r['php']['version'] ) . ' &middot; ' . esc_html( $r['php']['sapi_label'] );
		$php_val .= $r['php']['is_fixed']
			? ' <span class="p2s-pill p2s-ok">fixed version</span>'
			: ' <span class="p2s-pill p2s-bad">affected</span>';
		$this->row( 'PHP', $php_val );
		$this->row( 'Web server', esc_html( $r['server']['label'] ) . ' <span class="p2s-dim">(' . esc_html( $r['server']['software'] ) . ')</span>' );
		$this->row( 'In front of the site', esc_html( $r['proxy']['label'] ) );
		$this->row( 'Shield method here', esc_html( $r['shield']['method_label'] ) );

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
		$snippet = $shield->snippet();
		echo '<div class="p2s-card"><h2>Manual snippet</h2>';
		echo '<p class="p2s-dim">For your host, or if you prefer to apply it yourself (for example at PHP-FPM pool level, which survives everything).</p>';
		echo '<textarea class="p2s-snippet" rows="' . esc_attr( (string) ( substr_count( $snippet, "\n" ) + 1 ) ) . '" readonly="readonly" onclick="this.select()">' . esc_textarea( $snippet ) . '</textarea>';
		echo '</div>';
	}

	protected function row( $label, $value_html ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . $value_html . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- value pre-escaped by caller.
	}

	protected function tick( $ok ) {
		return $ok ? '<span class="p2s-pill p2s-ok">on</span>' : '<span class="p2s-pill p2s-bad">not set</span>';
	}

	protected function css() {
		return '
		.p2s-wrap{max-width:900px}
		.p2s-hero{display:flex;align-items:center;gap:16px;background:#0b0f10;color:#fff;border-radius:12px;padding:20px 24px;margin:16px 0}
		.p2s-hero-mark{font-size:34px;line-height:1}
		.p2s-hero-text h1{color:#fff;margin:0;font-size:24px}
		.p2s-hero-text p{color:#9aa0a6;margin:2px 0 0}
		.p2s-badge{margin-left:auto;font-weight:700;padding:6px 14px;border-radius:999px;font-size:13px}
		.p2s-card{background:#fff;border:1px solid #dcdcde;border-radius:10px;padding:18px 20px;margin:16px 0}
		.p2s-status{display:flex;gap:16px;align-items:flex-start}
		.p2s-status-body h2{margin-top:0}
		.p2s-light{width:18px;height:18px;border-radius:50%;margin-top:6px;flex:0 0 auto;box-shadow:0 0 0 4px rgba(0,0,0,.05)}
		.p2s-notes{margin:8px 0 0;padding-left:18px;color:#50575e}
		.p2s-honest{background:#fff8e5;border:1px solid #f0d58a;border-left:4px solid #dba617;border-radius:8px;padding:12px 16px;margin:16px 0;color:#4a3d12}
		.p2s-honest-inline{background:#fff8e5;border:1px solid #f0d58a;border-radius:8px;padding:10px 14px;color:#4a3d12}
		.p2s-verify{font-size:15px;padding:10px 14px;border-radius:8px;background:#f6f7f7}
		.p2s-ok-text{color:#137333}.p2s-warn-text{color:#9a6700}.p2s-bad-text{color:#c5221f}
		.p2s-finding{border-left:4px solid currentColor;padding:8px 14px;margin:10px 0;background:#f6f7f7;border-radius:0 8px 8px 0}
		.p2s-finding ul{color:#50575e}
		.p2s-table th{width:220px}
		.p2s-pill{display:inline-block;font-size:11px;font-weight:700;padding:1px 8px;border-radius:999px;vertical-align:middle}
		.p2s-dim{color:#8c8f94}
		.p2s-rescan{margin-top:12px}
		.p2s-snippet{width:100%;font-family:Menlo,Consolas,monospace;font-size:12px;background:#0b0f10;color:#d6f5d6;border-radius:8px;padding:12px;border:0}
		.p2s-ok{background:#e6f4ea;color:#137333}
		.p2s-warn{background:#fef7e0;color:#9a6700}
		.p2s-bad{background:#fce8e6;color:#c5221f}
		.p2s-badge.p2s-ok{background:#1e8e3e;color:#fff}
		.p2s-badge.p2s-warn{background:#f29900;color:#1b1b1b}
		.p2s-badge.p2s-bad{background:#d93025;color:#fff}
		.p2s-status.p2s-ok .p2s-light{background:#1e8e3e}
		.p2s-status.p2s-warn .p2s-light{background:#f29900}
		.p2s-status.p2s-bad .p2s-light{background:#d93025}
		.p2s-status.p2s-ok{border-color:#9fd8ae}
		.p2s-status.p2s-warn{border-color:#f3d07a}
		.p2s-status.p2s-bad{border-color:#f1b0ab}
		';
	}
}
