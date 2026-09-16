<?php
/**
 * Valida los paquetes publicados: reglas del WAF y firmas de malware.
 *
 *     php tools/validate.php                 # los dos paquetes del repositorio
 *     php tools/validate.php <ruta>          # un paquete suelto, del tipo que indique su campo «kind»
 */

require __DIR__ . '/lib.php';
require __DIR__ . '/signatures.php';

$paths = isset( $argv[1] ) ? array( (string) $argv[1] ) : array( AGR_PACKAGE, AGR_SIG_PACKAGE );

foreach ( $paths as $path ) {
	if ( ! is_file( $path ) ) {
		agr_fail( "No existe $path" );
	}

	$content = (string) file_get_contents( $path );
	$data    = json_decode( $content, true );
	$kind    = is_array( $data ) ? ( $data['kind'] ?? '' ) : '';
	$errors  = AGR_SIG_KIND === $kind ? agr_validate_signatures( $content ) : agr_validate( $content );

	if ( array() !== $errors ) {
		fwrite( STDERR, implode( "\n", $errors ) . "\n" );
		agr_fail( count( $errors ) . ' errores en ' . $path );
	}

	echo AGR_SIG_KIND === $kind
		? 'OK: ' . count( $data['signatures'] ) . ' firmas, versión ' . $data['serial'] . ' (' . $data['released'] . ")\n"
		: 'OK: ' . count( $data['rules'] ) . ' reglas, versión ' . $data['serial'] . ' (' . $data['released'] . ")\n";
}
