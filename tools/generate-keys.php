<?php
/**
 * Genera un par de claves de firma.
 *
 * Ejecutar SOLO en el equipo del responsable de firmar, nunca en un servidor ni en GitHub Actions.
 *
 *     php tools/generate-keys.php <fichero-clave-privada-fuera-del-repositorio>
 *
 * Después:
 *   1. Guardar el contenido del fichero de clave privada en el gestor de contraseñas y borrar el fichero.
 *   2. Añadir keys/<id>.pub al repositorio (es pública).
 *   3. Pasar la línea de Keys::TRUSTED a quien mantiene el plugin.
 */

require __DIR__ . '/lib.php';

agr_require_sodium();

$target = $argv[1] ?? '';

if ( '' === $target ) {
	agr_fail( 'Indica dónde escribir la clave privada, fuera del repositorio.' );
}

$root   = realpath( AGR_ROOT );
$parent = realpath( dirname( $target ) );

if ( false === $parent ) {
	agr_fail( 'La carpeta de destino no existe.' );
}

if ( 0 === strpos( strtolower( $parent . DIRECTORY_SEPARATOR ), strtolower( $root . DIRECTORY_SEPARATOR ) ) ) {
	agr_fail( 'La clave privada no puede guardarse dentro del repositorio.' );
}

if ( file_exists( $target ) ) {
	agr_fail( 'El fichero ya existe: no se sobrescribe una clave.' );
}

$pair   = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey( $pair );
$public = sodium_crypto_sign_publickey( $pair );
$id     = agr_key_id( $public );

if ( false === file_put_contents( $target, base64_encode( $secret ) . "\n" ) ) {
	agr_fail( 'No se pudo escribir la clave privada.' );
}

@chmod( $target, 0600 );

file_put_contents( AGR_ROOT . '/keys/' . $id . '.pub', base64_encode( $public ) . "\n" );

sodium_memzero( $secret );

echo "Clave privada: $target\n";
echo "  -> Cópiala al gestor de contraseñas y BORRA el fichero.\n\n";
echo 'Clave pública: keys/' . $id . ".pub (súbela al repositorio)\n\n";
echo "Línea para AirearteGuard\\Rules\\Keys::TRUSTED en el plugin:\n";
echo "\t'" . $id . "' => '" . base64_encode( $public ) . "',\n";
