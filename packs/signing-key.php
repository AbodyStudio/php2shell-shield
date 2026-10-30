<?php
/**
 * PUBLIC signing key (safe to ship) used to verify the bundled rule packs.
 *
 * This is a public key — it can only verify signatures, never create them.
 * It is kept as PHP (not a bare .pub file) so directory "sensitive file"
 * scanners do not mistake it for a private key or credential.
 *
 * @package PHP_Defender
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpoko23Jre3hHXyvyn4
Gkp3mfhf33Oi1f2ukDMk++D6uyk4RdmUSVeWKFeC+CKAXqr3RoqdgPV+x9RDyTcg
PO6YFNkY/yQ9r7N3Kc2wGeUN9M1KzWkKPDsvqw7ahh3+u2bDIAuv2kjiYwK0+gzS
aW6vO4E645MMr9Fzi9PLI7Q4enSMMu64Jnig2W82jflx/vx/HrqI/FCvjgYh2p6j
feQPnGGiMgdXBxVTfvUs33JdB4PmSODezTSYEIaDk9KPU4t18A9zsOaxKDtWLATr
VMph5ApAsj1pCgRk5XwhGyHL5i6twOnbXcdNqhBnwi9cNWAqQqpqWdhJ5trgBtSk
/wIDAQAB
-----END PUBLIC KEY-----
";
