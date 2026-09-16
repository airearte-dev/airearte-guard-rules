<?php
/**
 * Comprueba que una etiqueta se puede publicar.
 *
 *     php tools/publish-check.php <etiqueta> [carpeta con lo ya publicado]
 *
 * Reglas:
 *
 * - La etiqueta es `v<serial>` y ningún paquete puede llevar una versión mayor que ella: así la etiqueta identifica la
 *   publicación y nunca se queda por detrás de lo que contiene.
 * - Ningún paquete puede llevar una versión menor que la ya publicada: los sitios la rechazarían, pero mejor no llegar
 *   a publicarla.
 * - Al menos un paquete tiene que traer una versión nueva; si no, no hay nada que publicar.
 */

require __DIR__ . '/lib.php';
require __DIR__ . '/signatures.php';

$tag      = $argv[1] ?? '';
$previous = $argv[2] ?? '';
$packages = array(
	'waf-rules.json'         => AGR_PACKAGE,
	'malware-signatures.json' => AGR_SIG_PACKAGE,
);

if ( 1 !== preg_match( '/^v(\d+)$/', $tag, $match ) ) {
	agr_fail( "La etiqueta $tag no tiene la forma v<serial>" );
}

$tag_serial = (int) $match[1];
$newer      = false;

foreach ( $packages as $name => $path ) {
	if ( ! is_file( $path ) ) {
		agr_fail( "Falta el paquete $path" );
	}

	$serial = (int) ( json_decode( (string) file_get_contents( $path ), true )['serial'] ?? 0 );

	if ( $serial < 1 ) {
		agr_fail( "$name: no se ha podido leer la versión" );
	}

	if ( $serial > $tag_serial ) {
		agr_fail( "$name: la versión $serial es mayor que la etiqueta $tag" );
	}

	$published = '' !== $previous && is_file( $previous . '/' . $name )
		? (int) ( json_decode( (string) file_get_contents( $previous . '/' . $name ), true )['serial'] ?? 0 )
		: 0;

	if ( $serial < $published ) {
		agr_fail( "$name: la versión $serial es menor que la publicada $published" );
	}

	if ( $serial > $published ) {
		$newer = true;
	}

	echo "$name: versión $serial (publicada: " . ( $published > 0 ? $published : 'ninguna' ) . ")\n";
}

if ( ! $newer ) {
	agr_fail( 'Ningún paquete trae una versión nueva.' );
}

echo "Se puede publicar $tag.\n";
