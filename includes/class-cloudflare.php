<?php
/**
 * Minimal Cloudflare client for PHP2Shell Shield.
 *
 * Deploys the edge filter (and an optional lockdown) as custom firewall rules
 * in the zone's http_request_firewall_custom ruleset. Rule management is
 * NON-DESTRUCTIVE: it reads the existing rules, removes only the ones tagged as
 * ours (by a marker in the description), adds the new one, and writes the full
 * list back — so the user's own Cloudflare rules are never touched.
 *
 * The HTTP transport is injectable so the request-building logic can be tested
 * without a live account or network.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Cloudflare {

	const API   = 'https://api.cloudflare.com/client/v4';
	const PHASE = 'http_request_firewall_custom';

	/** @var string */
	protected $token;

	/** @var string */
	protected $zone_id;

	/** @var callable|null Injected transport(method,url,headers,body)->array(code,body). */
	protected $transport;

	public function __construct( $token, $zone_id = '', $transport = null ) {
		$this->token     = (string) $token;
		$this->zone_id   = (string) $zone_id;
		$this->transport = $transport;
	}

	/* ---- HTTP ---------------------------------------------------------- */

	protected function http( $method, $url, $body = null ) {
		$headers = array(
			'Authorization' => 'Bearer ' . $this->token,
			'Content-Type'  => 'application/json',
		);
		$json = ( null === $body ) ? null : ( function_exists( 'wp_json_encode' ) ? wp_json_encode( $body ) : json_encode( $body ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- wp_json_encode used when available; plain json_encode only in CLI tests.

		if ( is_callable( $this->transport ) ) {
			$res = call_user_func( $this->transport, $method, $url, $headers, $json );
		} else {
			$res = $this->default_transport( $method, $url, $headers, $json );
		}

		$code = isset( $res['code'] ) ? (int) $res['code'] : 0;
		$data = isset( $res['body'] ) ? json_decode( $res['body'], true ) : null;
		return array( 'code' => $code, 'data' => $data );
	}

	protected function default_transport( $method, $url, $headers, $json ) {
		if ( ! function_exists( 'wp_remote_request' ) ) {
			return array( 'code' => 0, 'body' => '' );
		}
		$args = array(
			'method'  => $method,
			'headers' => $headers,
			'timeout' => 15,
		);
		if ( null !== $json ) {
			$args['body'] = $json;
		}
		$resp = wp_remote_request( $url, $args );
		if ( is_wp_error( $resp ) ) {
			return array( 'code' => 0, 'body' => '' );
		}
		return array(
			'code' => (int) wp_remote_retrieve_response_code( $resp ),
			'body' => wp_remote_retrieve_body( $resp ),
		);
	}

	/* ---- API calls ----------------------------------------------------- */

	/** Verify the token is valid and active. */
	public function verify_token() {
		$r = $this->http( 'GET', self::API . '/user/tokens/verify' );
		$ok = ( 200 === $r['code'] && isset( $r['data']['success'] ) && $r['data']['success'] );
		return array( 'ok' => $ok, 'code' => $r['code'] );
	}

	/** Look up the zone id for a domain. */
	public function find_zone( $domain ) {
		$domain = preg_replace( '/^www\./', '', strtolower( trim( (string) $domain ) ) );
		$r      = $this->http( 'GET', self::API . '/zones?name=' . rawurlencode( $domain ) );
		if ( 200 === $r['code'] && ! empty( $r['data']['result'][0]['id'] ) ) {
			$this->zone_id = $r['data']['result'][0]['id'];
			return array( 'ok' => true, 'zone_id' => $this->zone_id );
		}
		return array( 'ok' => false, 'code' => $r['code'] );
	}

	protected function entrypoint_url() {
		return self::API . '/zones/' . $this->zone_id . '/rulesets/phases/' . self::PHASE . '/entrypoint';
	}

	/** Read the current custom-firewall rules (empty list if none yet). */
	public function get_rules() {
		$r = $this->http( 'GET', $this->entrypoint_url() );
		if ( 200 === $r['code'] && isset( $r['data']['result']['rules'] ) && is_array( $r['data']['result']['rules'] ) ) {
			return $r['data']['result']['rules'];
		}
		// 404 = no ruleset yet; treat as empty.
		return array();
	}

	/**
	 * Deploy (or update) one of our rules, preserving every other rule.
	 *
	 * @param string $ref        Stable marker, e.g. "p2s:filter".
	 * @param string $expression Cloudflare rule expression.
	 * @param string $action     "block" (default).
	 * @return array
	 */
	public function deploy_rule( $ref, $expression, $action = 'block' ) {
		if ( '' === $this->zone_id ) {
			return array( 'ok' => false, 'reason' => 'no_zone' );
		}
		$marker = '[' . $ref . ']';
		$rules  = $this->keep_others( $this->get_rules(), $marker );
		$rules[] = array(
			'action'      => $action,
			'expression'  => $expression,
			'description' => 'PHP2Shell Shield ' . $marker,
			'enabled'     => true,
		);
		$r = $this->http( 'PUT', $this->entrypoint_url(), array( 'rules' => $rules ) );
		$ok = ( 200 === $r['code'] && isset( $r['data']['success'] ) && $r['data']['success'] );
		return array( 'ok' => $ok, 'code' => $r['code'] );
	}

	/** Remove our rule by ref, preserving every other rule. */
	public function remove_rule( $ref ) {
		if ( '' === $this->zone_id ) {
			return array( 'ok' => false, 'reason' => 'no_zone' );
		}
		$marker = '[' . $ref . ']';
		$rules  = $this->keep_others( $this->get_rules(), $marker );
		$r      = $this->http( 'PUT', $this->entrypoint_url(), array( 'rules' => $rules ) );
		$ok     = ( 200 === $r['code'] && isset( $r['data']['success'] ) && $r['data']['success'] );
		return array( 'ok' => $ok, 'code' => $r['code'] );
	}

	/** Filter out rules whose description carries our marker. */
	protected function keep_others( $rules, $marker ) {
		$out = array();
		foreach ( $rules as $rule ) {
			$desc = isset( $rule['description'] ) ? $rule['description'] : '';
			if ( false !== strpos( $desc, $marker ) ) {
				continue;
			}
			// Re-send only the fields Cloudflare expects back.
			$keep = array();
			foreach ( array( 'action', 'expression', 'description', 'enabled', 'action_parameters', 'ref', 'id' ) as $k ) {
				if ( isset( $rule[ $k ] ) ) {
					$keep[ $k ] = $rule[ $k ];
				}
			}
			$out[] = $keep;
		}
		return $out;
	}

	public function zone_id() {
		return $this->zone_id;
	}
}
