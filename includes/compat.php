<?php
/**
 * PHP 5.4-safe helper functions.
 *
 * We cannot use str_starts_with / str_contains (PHP 8.0) or the null
 * coalescing operator, so the small helpers we need live here.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'p2s_str_contains' ) ) {
	/**
	 * Case-insensitive "does haystack contain needle".
	 *
	 * @param string $haystack Haystack.
	 * @param string $needle   Needle.
	 * @return bool
	 */
	function p2s_str_contains( $haystack, $needle ) {
		if ( '' === $needle ) {
			return true;
		}
		return false !== stripos( (string) $haystack, (string) $needle );
	}
}

if ( ! function_exists( 'p2s_server' ) ) {
	/**
	 * Safe read from $_SERVER with a default (no ?? on PHP 5.4).
	 *
	 * @param string $key     Key.
	 * @param mixed  $default Default.
	 * @return mixed
	 */
	function p2s_server( $key, $default = '' ) {
		if ( ! isset( $_SERVER[ $key ] ) ) {
			return $default;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- unslashed + sanitised just below when WordPress is loaded; raw only in CLI tests, and every caller escapes on output.
		$v = $_SERVER[ $key ];
		if ( function_exists( 'wp_unslash' ) ) {
			$v = wp_unslash( $v );
		}
		if ( function_exists( 'sanitize_text_field' ) ) {
			$v = sanitize_text_field( $v );
		}
		return $v;
	}
}

// OPENSSL_ALGO_SHA256 was only added in PHP 5.4.8. On 5.4.0–5.4.7 it is
// undefined, which would break signature verification, so define its known
// value (7) as a fallback. No-op where OpenSSL already defines it.
if ( ! defined( 'OPENSSL_ALGO_SHA256' ) ) {
	define( 'OPENSSL_ALGO_SHA256', 7 );
}

if ( ! function_exists( 'p2s_random_string' ) ) {
	/**
	 * A cryptographically random string from a quote-safe charset, using the
	 * best source available (random_bytes on PHP 7+, else OpenSSL, else a
	 * weaker fallback). The charset excludes quotes, backslash, dollar and
	 * backtick so the result is always safe inside a single-quoted PHP string.
	 *
	 * @param int $len Length.
	 * @return string
	 */
	function p2s_random_string( $len = 64 ) {
		$chars = '';
		for ( $i = 33; $i <= 126; $i++ ) {
			$c = chr( $i );
			if ( "'" === $c || '"' === $c || '\\' === $c || '$' === $c || '`' === $c ) {
				continue;
			}
			$chars .= $c;
		}
		$max = strlen( $chars ) - 1;

		$bytes = '';
		if ( function_exists( 'random_bytes' ) ) {
			try {
				// phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions.random_bytesFound -- guarded by function_exists; never called on PHP < 7.0.
				$bytes = random_bytes( $len );
			} catch ( Exception $e ) {
				$bytes = '';
			}
		}
		if ( '' === $bytes && function_exists( 'openssl_random_pseudo_bytes' ) ) {
			$strong = false;
			$bytes  = openssl_random_pseudo_bytes( $len, $strong );
			if ( ! $strong ) {
				$bytes = '';
			}
		}

		$out = '';
		if ( '' !== $bytes && strlen( $bytes ) >= $len ) {
			for ( $i = 0; $i < $len; $i++ ) {
				$out .= $chars[ ord( $bytes[ $i ] ) % ( $max + 1 ) ];
			}
			return $out;
		}

		// Last-resort fallback, only if random_bytes AND OpenSSL are both
		// unavailable. Uses wp_rand in WordPress; mt_rand only in CLI tests.
		for ( $i = 0; $i < $len; $i++ ) {
			if ( function_exists( 'wp_rand' ) ) {
				$r = wp_rand( 0, $max );
			} else {
				$r = mt_rand( 0, $max ); // phpcs:ignore WordPress.WP.AlternativeFunctions.rand_mt_rand -- wp_rand is used under WordPress; this branch is a CLI-only last resort.
			}
			$out .= $chars[ $r ];
		}
		return $out;
	}
}

if ( ! function_exists( 'p2s_hash_equals' ) ) {
	/**
	 * Constant-time string compare. Uses hash_equals (PHP 5.6+) when available,
	 * else a constant-time fallback for PHP 5.4/5.5.
	 *
	 * @param string $known Known string.
	 * @param string $given User-supplied string.
	 * @return bool
	 */
	function p2s_hash_equals( $known, $given ) {
		if ( function_exists( 'hash_equals' ) ) {
			// phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions.hash_equalsFound -- guarded by function_exists; the fallback below covers PHP < 5.6.
			return hash_equals( (string) $known, (string) $given );
		}
		$known = (string) $known;
		$given = (string) $given;
		$n     = strlen( $known );
		if ( $n !== strlen( $given ) ) {
			return false;
		}
		$r = 0;
		for ( $i = 0; $i < $n; $i++ ) {
			$r |= ord( $known[ $i ] ) ^ ord( $given[ $i ] );
		}
		return 0 === $r;
	}
}

if ( ! function_exists( 'p2s_opt_get' ) ) {
	/**
	 * Option storage that uses WordPress when present, else an in-memory store
	 * (for CLI testing). All plugin classes share this so state is consistent.
	 */
	function p2s_opt_get( $k ) {
		if ( function_exists( 'get_option' ) ) {
			$v = get_option( $k );
			return ( false === $v ) ? null : $v;
		}
		return isset( $GLOBALS['__p2s_mem'][ $k ] ) ? $GLOBALS['__p2s_mem'][ $k ] : null;
	}
	function p2s_opt_set( $k, $v ) {
		if ( function_exists( 'update_option' ) ) {
			update_option( $k, $v );
			return;
		}
		if ( ! isset( $GLOBALS['__p2s_mem'] ) ) {
			$GLOBALS['__p2s_mem'] = array();
		}
		$GLOBALS['__p2s_mem'][ $k ] = $v;
	}
	function p2s_opt_delete( $k ) {
		if ( function_exists( 'delete_option' ) ) {
			delete_option( $k );
			return;
		}
		unset( $GLOBALS['__p2s_mem'][ $k ] );
	}
}

if ( ! function_exists( 'p2s_remote_addr' ) ) {
	/**
	 * The IP the web server actually matches on (REMOTE_ADDR). Behind a proxy
	 * like Cloudflare this is the proxy's IP, which is why server-level IP rules
	 * are unreliable behind Cloudflare.
	 *
	 * @return string
	 */
	function p2s_remote_addr() {
		$ip = p2s_server( 'REMOTE_ADDR', '' );
		return preg_replace( '/[^0-9a-fA-F:\.]/', '', (string) $ip );
	}
}

if ( ! function_exists( 'p2s_real_ip' ) ) {
	/**
	 * The real visitor IP: Cloudflare's CF-Connecting-IP when present, else
	 * REMOTE_ADDR. Use this for Cloudflare-side rules (ip.src), never for
	 * server-side Require/Allow directives.
	 *
	 * @return string
	 */
	function p2s_real_ip() {
		$cf = p2s_server( 'HTTP_CF_CONNECTING_IP', '' );
		if ( '' !== $cf ) {
			return preg_replace( '/[^0-9a-fA-F:\.]/', '', (string) $cf );
		}
		return p2s_remote_addr();
	}
}

if ( ! function_exists( 'p2s_is_ip' ) ) {
	/**
	 * Validate an IPv4 or IPv6 address.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	function p2s_is_ip( $ip ) {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP );
	}
}

if ( ! function_exists( 'p2s_secret_key' ) ) {
	/**
	 * A per-site key for light obfuscation of stored secrets. Uses WP salts
	 * when available. This is obfuscation, not strong encryption (libsodium is
	 * unavailable on PHP 5.4); it keeps a token from sitting in the database as
	 * plain text, nothing more.
	 *
	 * @return string
	 */
	function p2s_secret_key() {
		if ( defined( 'AUTH_SALT' ) && AUTH_SALT ) {
			return hash( 'sha256', 'p2s|' . AUTH_SALT );
		}
		if ( defined( 'AUTH_KEY' ) && AUTH_KEY ) {
			return hash( 'sha256', 'p2s|' . AUTH_KEY );
		}
		return hash( 'sha256', 'p2s|fallback-not-secret' );
	}
}

if ( ! function_exists( 'p2s_obfuscate' ) ) {
	/**
	 * Reversibly obfuscate a short secret (XOR with the site key, base64).
	 *
	 * @param string $plain Secret.
	 * @return string
	 */
	function p2s_obfuscate( $plain ) {
		$key = p2s_secret_key();
		$kl  = strlen( $key );
		$out = '';
		$pl  = strlen( $plain );
		for ( $i = 0; $i < $pl; $i++ ) {
			$out .= chr( ord( $plain[ $i ] ) ^ ord( $key[ $i % $kl ] ) );
		}
		return base64_encode( $out );
	}

	/**
	 * Reverse p2s_obfuscate().
	 *
	 * @param string $blob Obfuscated string.
	 * @return string
	 */
	function p2s_deobfuscate( $blob ) {
		$raw = base64_decode( (string) $blob, true );
		if ( false === $raw ) {
			return '';
		}
		$key = p2s_secret_key();
		$kl  = strlen( $key );
		$out = '';
		$rl  = strlen( $raw );
		for ( $i = 0; $i < $rl; $i++ ) {
			$out .= chr( ord( $raw[ $i ] ) ^ ord( $key[ $i % $kl ] ) );
		}
		return $out;
	}
}

if ( ! function_exists( 'p2s_ini_truthy' ) ) {
	/**
	 * Is a php.ini flag effectively ON?
	 *
	 * ini_get() returns strings like "1", "0", "", "On", "Off".
	 *
	 * @param string $value Raw ini_get value.
	 * @return bool
	 */
	function p2s_ini_truthy( $value ) {
		if ( false === $value || null === $value ) {
			return false;
		}
		$v = strtolower( trim( (string) $value ) );
		if ( '' === $v || '0' === $v || 'off' === $v || 'false' === $v || 'no' === $v ) {
			return false;
		}
		return true;
	}
}

if ( ! function_exists( 'p2s_ini_bytes' ) ) {
	/**
	 * Parse a php.ini shorthand byte value ("32M", "128K", "1G", "-1") to bytes.
	 *
	 * Returns PHP_INT_MAX for an unlimited value (-1 or empty), so callers can
	 * treat "unlimited" as "larger than any cap".
	 *
	 * @param string|int $value Raw ini value.
	 * @return int Bytes (PHP_INT_MAX for unlimited).
	 */
	function p2s_ini_bytes( $value ) {
		$v = trim( (string) $value );
		if ( '' === $v || '-1' === $v ) {
			return PHP_INT_MAX;
		}
		$unit = strtolower( substr( $v, -1 ) );
		$num  = (float) $v; // leading numeric part; ignores a trailing letter.
		if ( 'g' === $unit ) {
			$num *= 1024 * 1024 * 1024;
		} elseif ( 'm' === $unit ) {
			$num *= 1024 * 1024;
		} elseif ( 'k' === $unit ) {
			$num *= 1024;
		}
		if ( $num < 0 ) {
			return PHP_INT_MAX;
		}
		return (int) $num;
	}
}
