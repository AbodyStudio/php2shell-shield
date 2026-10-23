<?php
/**
 * Safe config-file editing for PHP2Shell Shield.
 *
 * Only ever touches a block between our own sentinels, so the rest of the
 * user's file is never disturbed. Writes atomically (temp file + rename) so a
 * half-written file can never 500 the site, and refuses to write anywhere
 * outside the directory it was given.
 *
 * WordPress-independent so it can be tested from the CLI.
 *
 * @package PHP2Shell_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class P2S_Files {

	const BEGIN = 'BEGIN PHP2Shell Shield';
	const END   = 'END PHP2Shell Shield';

	/**
	 * Base directory we are allowed to write into (normally ABSPATH).
	 *
	 * @var string
	 */
	protected $base;

	/**
	 * @param string $base Directory writes are confined to.
	 */
	public function __construct( $base ) {
		$this->base = rtrim( $base, '/\\' ) . '/';
	}

	/**
	 * Absolute path for a filename inside the base dir. Refuses traversal.
	 *
	 * @param string $name e.g. ".user.ini"
	 * @return string|false
	 */
	public function path( $name ) {
		$name = ltrim( $name, '/\\' );
		if ( false !== strpos( $name, '..' ) ) {
			return false;
		}
		return $this->base . $name;
	}

	/**
	 * Read a file, returning '' if it does not exist.
	 *
	 * @param string $name Filename.
	 * @return string
	 */
	public function read( $name ) {
		$p = $this->path( $name );
		if ( false === $p || ! file_exists( $p ) ) {
			return '';
		}
		$c = file_get_contents( $p );
		return ( false === $c ) ? '' : $c;
	}

	/**
	 * Does the file exist?
	 *
	 * @param string $name Filename.
	 * @return bool
	 */
	public function exists( $name ) {
		$p = $this->path( $name );
		return ( false !== $p && file_exists( $p ) );
	}

	/**
	 * Can we create/modify this file? (writable file, or writable dir if new.)
	 *
	 * @param string $name Filename.
	 * @return bool
	 */
	public function writable( $name ) {
		$p = $this->path( $name );
		if ( false === $p ) {
			return false;
		}
		if ( file_exists( $p ) ) {
			return is_writable( $p ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
		}
		return is_writable( dirname( $p ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
	}

	/**
	 * Comment syntax differs: ".ini" files use ';', others (.htaccess) use '#'.
	 *
	 * @param string $name Filename.
	 * @return string
	 */
	protected function comment_char( $name ) {
		if ( false !== stripos( $name, '.ini' ) ) {
			return ';';
		}
		return '#';
	}

	/** Begin/end marker text for a (possibly labelled) block. */
	protected function begin_marker( $label ) {
		return self::BEGIN . ( '' !== $label ? ': ' . $label : '' );
	}
	protected function end_marker( $label ) {
		return self::END . ( '' !== $label ? ': ' . $label : '' );
	}

	/**
	 * Return $content with OUR block for $label removed.
	 *
	 * The marker must be followed by end-of-line, so stripping the unlabelled
	 * block never accidentally eats a labelled one (e.g. ": Filter"), and vice
	 * versa. This keeps the shield, filter, and lockdown blocks independent in
	 * the same file.
	 *
	 * @param string $content File content.
	 * @param string $label   Block label ('' for the main shield block).
	 * @return string
	 */
	public function strip_block( $content, $label = '' ) {
		if ( '' === $content ) {
			return '';
		}
		$b = preg_quote( $this->begin_marker( $label ), '/' );
		$e = preg_quote( $this->end_marker( $label ), '/' );
		// Begin marker must end its line; end marker likewise.
		$pattern = '/[ \t]*(?:#|;)[ \t]*' . $b . '[ \t]*\R.*?(?:#|;)[ \t]*' . $e . '[ \t]*\R?/s';
		$out     = preg_replace( $pattern, '', $content );
		if ( null === $out ) {
			return $content;
		}
		return ltrim( $out, "\r\n" );
	}

	/**
	 * Insert (or replace) a labelled block carrying $lines, at the top.
	 *
	 * @param string   $content Existing content.
	 * @param string[] $lines   Directive lines to place inside the block.
	 * @param string   $name    Filename (chooses comment char).
	 * @param string   $label   Block label ('' for the main shield block).
	 * @return string New content.
	 */
	public function set_block( $content, $lines, $name, $label = '' ) {
		$c     = $this->comment_char( $name );
		$body  = implode( "\n", $lines );
		$block = $c . ' ' . $this->begin_marker( $label ) . "\n" . $body . "\n" . $c . ' ' . $this->end_marker( $label ) . "\n";
		$rest  = $this->strip_block( $content, $label );
		if ( '' === trim( $rest ) ) {
			return $block;
		}
		return $block . "\n" . $rest;
	}

	/** Does our labelled block exist in $content? */
	public function has_block( $content, $label = '' ) {
		$b = preg_quote( $this->begin_marker( $label ), '/' );
		return (bool) preg_match( '/(?:#|;)[ \t]*' . $b . '[ \t]*\R/', (string) $content );
	}

	/**
	 * Atomically write content to the file (temp + rename).
	 *
	 * @param string $name    Filename.
	 * @param string $content Content.
	 * @return bool
	 */
	public function write( $name, $content ) {
		$p = $this->path( $name );
		if ( false === $p ) {
			return false;
		}
		$tmp = $p . '.p2s-tmp-' . substr( md5( uniqid( 'p2s', true ) ), 0, 8 );
		$bytes = file_put_contents( $tmp, $content, LOCK_EX );
		if ( false === $bytes ) {
			return false;
		}
		// Match the surrounding dir's perms loosely; keep it readable by the server.
		@chmod( $tmp, 0644 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
		if ( ! @rename( $tmp, $p ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- direct filesystem op required: atomic config writes + auto-revert, no FS-credential prompt.
			@unlink( $tmp );
			return false;
		}
		return true;
	}

	/**
	 * Delete the file.
	 *
	 * @param string $name Filename.
	 * @return bool
	 */
	public function delete( $name ) {
		$p = $this->path( $name );
		if ( false === $p || ! file_exists( $p ) ) {
			return true;
		}
		return @unlink( $p );
	}
}
