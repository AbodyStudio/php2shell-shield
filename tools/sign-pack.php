<?php
/**
 * Sign a rule pack for PHP2Shell Shield.
 *
 * Produces a detached RSA-SHA256 signature (base64) over the EXACT bytes of
 * the pack .json file. The plugin verifies those same bytes against the
 * bundled public key, so no JSON re-serialisation is involved.
 *
 * Usage:
 *   php tools/sign-pack.php packs/php2shell.pack.json keys/p2s-private.pem
 *
 * Writes:  packs/php2shell.pack.sig   (base64 signature)
 *
 * The private key must NEVER be committed or shipped in the plugin zip.
 *
 * @package PHP2Shell_Shield
 */

if ( PHP_SAPI !== 'cli' ) {
	fwrite( STDERR, "Run from the command line.\n" );
	exit( 1 );
}
if ( $argc < 3 ) {
	fwrite( STDERR, "Usage: php tools/sign-pack.php <pack.json> <private-key.pem>\n" );
	exit( 1 );
}

$pack_file = $argv[1];
$key_file  = $argv[2];

if ( ! file_exists( $pack_file ) ) {
	fwrite( STDERR, "Pack not found: $pack_file\n" );
	exit( 1 );
}
if ( ! file_exists( $key_file ) ) {
	fwrite( STDERR, "Private key not found: $key_file\n" );
	exit( 1 );
}

$data = file_get_contents( $pack_file );

// Sanity: must be valid JSON before we sign it.
$decoded = json_decode( $data, true );
if ( ! is_array( $decoded ) ) {
	fwrite( STDERR, "Pack is not valid JSON; refusing to sign.\n" );
	exit( 1 );
}

$pkey = openssl_pkey_get_private( file_get_contents( $key_file ) );
if ( false === $pkey ) {
	fwrite( STDERR, "Could not load private key.\n" );
	exit( 1 );
}

$sig = '';
if ( ! openssl_sign( $data, $sig, $pkey, OPENSSL_ALGO_SHA256 ) ) {
	fwrite( STDERR, "Signing failed.\n" );
	exit( 1 );
}

$sig_file = preg_replace( '/\.json$/', '.sig', $pack_file );
file_put_contents( $sig_file, base64_encode( $sig ) . "\n" );

echo "Signed: $pack_file\n";
echo "Wrote:  $sig_file\n";
echo 'Pack:   ' . ( isset( $decoded['id'] ) ? $decoded['id'] : '?' ) . ' v' . ( isset( $decoded['pack_version'] ) ? $decoded['pack_version'] : '?' ) . "\n";
