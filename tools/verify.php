<?php
/**
 * Verifica un paquete firmado con las claves públicas del repositorio.
 *
 *     php tools/verify.php [paquete] [firma]
 */

require __DIR__ . '/lib.php';

agr_require_sodium();

$package   = $argv[1] ?? AGR_DIST . '/waf-rules.json';
$signature = $argv[2] ?? $package . '.sig';

foreach ( array( $package, $signature ) as $file ) {
	if ( ! is_file( $file ) ) {
		agr_fail( "No existe $file" );
	}
}

$content = (string) file_get_contents( $package );
$id      = agr_verify( $content, (string) file_get_contents( $signature ), agr_public_keys() );

if ( '' === $id ) {
	agr_fail( 'Firma NO válida.' );
}

$errors = agr_validate( $content );

if ( array() !== $errors ) {
	fwrite( STDERR, implode( "\n", $errors ) . "\n" );
	agr_fail( 'Firma válida, pero el paquete no pasa la validación.' );
}

echo "OK: firma válida (clave $id) y paquete válido.\n";
