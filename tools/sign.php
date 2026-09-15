<?php
/**
 * Valida y firma el paquete de reglas para publicarlo.
 *
 * Ejecutar SOLO en el equipo del responsable de firmar.
 *
 *     php tools/sign.php <fichero-clave-privada | ->
 *
 * Con "-" la clave se lee de la entrada estándar: se puede pegar desde el gestor de contraseñas sin dejarla en disco.
 * Deja en dist/ los dos ficheros que se suben a la release: waf-rules.json y waf-rules.json.sig.
 */

require __DIR__ . '/lib.php';

agr_require_sodium();

$source = $argv[1] ?? '';

if ( '' === $source ) {
	agr_fail( 'Indica el fichero de la clave privada, o - para pegarla.' );
}

if ( '-' === $source ) {
	fwrite( STDERR, "Pega la clave privada y pulsa Intro:\n" );
	$encoded = trim( (string) fgets( STDIN ) );
} else {
	$encoded = trim( (string) @file_get_contents( $source ) );
}

$secret = base64_decode( $encoded, true );

if ( ! is_string( $secret ) || SODIUM_CRYPTO_SIGN_SECRETKEYBYTES !== strlen( $secret ) ) {
	agr_fail( 'La clave privada no es válida.' );
}

$content = (string) file_get_contents( AGR_PACKAGE );
$errors  = agr_validate( $content );

if ( array() !== $errors ) {
	fwrite( STDERR, implode( "\n", $errors ) . "\n" );
	agr_fail( 'El paquete no es válido: no se firma.' );
}

$public = sodium_crypto_sign_publickey_from_secretkey( $secret );
$id     = agr_key_id( $public );
$keys   = agr_public_keys();

if ( ! isset( $keys[ $id ] ) ) {
	agr_fail( "La clave pública de esta clave privada ($id) no está en keys/: el plugin no aceptaría la firma." );
}

$signature = json_encode(
	array(
		'format'    => 1,
		'key'       => $id,
		'signature' => base64_encode( sodium_crypto_sign_detached( agr_message( AGR_KIND, $content ), $secret ) ),
	)
) . "\n";

sodium_memzero( $secret );

if ( agr_verify( $content, $signature, $keys ) !== $id ) {
	agr_fail( 'La firma recién creada no se verifica.' );
}

if ( ! is_dir( AGR_DIST ) ) {
	mkdir( AGR_DIST );
}

// Se copian los bytes exactos: cualquier cambio posterior, aunque sea un salto de línea, invalida la firma.
file_put_contents( AGR_DIST . '/waf-rules.json', $content );
file_put_contents( AGR_DIST . '/waf-rules.json.sig', $signature );

$data = json_decode( $content, true );

echo 'Firmado con la clave ' . $id . ': versión ' . $data['serial'] . ', ' . count( $data['rules'] ) . " reglas.\n";
echo "Sube dist/waf-rules.json y dist/waf-rules.json.sig a una release con la etiqueta v" . $data['serial'] . ".\n";
