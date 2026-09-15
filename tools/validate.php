<?php
/**
 * Valida el paquete de reglas.
 *
 *     php tools/validate.php [ruta]
 */

require __DIR__ . '/lib.php';

$path = $argv[1] ?? AGR_PACKAGE;

if ( ! is_file( $path ) ) {
	agr_fail( "No existe $path" );
}

$errors = agr_validate( (string) file_get_contents( $path ) );

if ( array() !== $errors ) {
	fwrite( STDERR, implode( "\n", $errors ) . "\n" );
	agr_fail( count( $errors ) . ' errores en ' . $path );
}

$data = json_decode( (string) file_get_contents( $path ), true );

echo 'OK: ' . count( $data['rules'] ) . ' reglas, versión ' . $data['serial'] . ' (' . $data['released'] . ")\n";
