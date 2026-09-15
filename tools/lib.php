<?php
/**
 * Funciones comunes de las herramientas del repositorio de reglas.
 *
 * Deben coincidir con el plugin (AirearteGuard\Rules\Signature y Package). Si cambian allí, cambian aquí.
 */

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

const AGR_ROOT         = __DIR__ . '/..';
const AGR_KIND         = 'waf-rules';
const AGR_PACKAGE      = AGR_ROOT . '/packages/waf-rules.json';
const AGR_DIST         = AGR_ROOT . '/dist';
const AGR_MAX_BYTES    = 1048576;
const AGR_TARGETS      = array( 'uri', 'args', 'args_names', 'cookies', 'headers', 'files' );
const AGR_TRANSFORMS   = array( 'urldecode', 'html', 'lowercase', 'compress', 'sql_comments', 'null_bytes', 'path' );
const AGR_PACKAGE_KEYS = array( 'format', 'kind', 'serial', 'released', 'min_plugin', 'notes', 'rules' );
const AGR_RULE_KEYS    = array( 'id', 'category', 'targets', 'transforms', 'pattern', 'fast', 'admin_exempt', 'description' );

/**
 * Termina con un error.
 */
function agr_fail( string $message ) {
	fwrite( STDERR, "ERROR: $message\n" );
	exit( 1 );
}

/**
 * Comprueba que hay Ed25519.
 */
function agr_require_sodium() {
	if ( ! function_exists( 'sodium_crypto_sign_detached' ) ) {
		agr_fail( 'PHP necesita la extensión sodium (en Windows: extension=sodium en php.ini).' );
	}
}

/**
 * Texto firmado. Igual que Signature::message() del plugin.
 */
function agr_message( string $kind, string $content ): string {
	return 'AirearteGuard signed package v1' . "\n" . $kind . "\n" . $content;
}

/**
 * Identificador de una clave pública. Igual que Signature::keyId() del plugin.
 */
function agr_key_id( string $public_key ): string {
	return substr( hash( 'sha256', $public_key ), 0, 16 );
}

/**
 * Claves públicas del repositorio: keys/<id>.pub con la clave en base64.
 *
 * @return array<string,string> id => clave binaria
 */
function agr_public_keys(): array {
	$keys = array();

	foreach ( glob( AGR_ROOT . '/keys/*.pub' ) as $file ) {
		$key = base64_decode( trim( (string) file_get_contents( $file ) ), true );
		$id  = basename( $file, '.pub' );

		if ( ! is_string( $key ) || 32 !== strlen( $key ) || agr_key_id( $key ) !== $id ) {
			agr_fail( "Clave pública no válida o con nombre incorrecto: $file" );
		}

		$keys[ $id ] = $key;
	}

	return $keys;
}

/**
 * Verifica una firma. Devuelve el id de la clave o cadena vacía.
 */
function agr_verify( string $content, string $signature, array $keys ): string {
	$data = json_decode( $signature, true );

	if ( ! is_array( $data ) || 1 !== ( $data['format'] ?? null ) || ! is_string( $data['key'] ?? null ) || ! is_string( $data['signature'] ?? null ) ) {
		return '';
	}

	$raw = base64_decode( $data['signature'], true );

	if ( ! isset( $keys[ $data['key'] ] ) || ! is_string( $raw ) || 64 !== strlen( $raw ) ) {
		return '';
	}

	return sodium_crypto_sign_verify_detached( $raw, agr_message( AGR_KIND, $content ), $keys[ $data['key'] ] ) ? $data['key'] : '';
}

/**
 * Valida un paquete con las mismas reglas de formato que el plugin.
 *
 * El plugin además prueba cada regla contra peticiones normales con su motor completo; aquí se hace una
 * aproximación. Si el plugin rechaza un paquete que aquí pasa, se corrige aquí.
 *
 * @return string[] Errores.
 */
function agr_validate( string $content ): array {
	$errors = array();

	if ( '' === $content || strlen( $content ) > AGR_MAX_BYTES ) {
		return array( 'Tamaño fuera de límites (máximo 1 MB).' );
	}

	$data = json_decode( $content, true, 32 );

	if ( ! is_array( $data ) ) {
		return array( 'No es JSON válido: ' . json_last_error_msg() );
	}

	foreach ( array_diff( array_keys( $data ), AGR_PACKAGE_KEYS ) as $key ) {
		$errors[] = "Campo desconocido en el paquete: $key";
	}

	if ( 1 !== ( $data['format'] ?? null ) ) {
		$errors[] = 'format debe ser 1';
	}

	if ( AGR_KIND !== ( $data['kind'] ?? null ) ) {
		$errors[] = 'kind debe ser ' . AGR_KIND;
	}

	if ( ! is_int( $data['serial'] ?? null ) || $data['serial'] < 1 ) {
		$errors[] = 'serial debe ser un entero positivo (AAAAMMDDNN)';
	}

	if ( ! is_string( $data['released'] ?? null ) || 1 !== preg_match( '/^\d{4}-\d{2}-\d{2}$/', $data['released'] ) ) {
		$errors[] = 'released debe ser una fecha AAAA-MM-DD';
	}

	if ( isset( $data['min_plugin'] ) && ( ! is_string( $data['min_plugin'] ) || 1 !== preg_match( '/^\d+\.\d+\.\d+$/', $data['min_plugin'] ) ) ) {
		$errors[] = 'min_plugin debe ser una versión X.Y.Z';
	}

	$rules = $data['rules'] ?? null;

	if ( ! is_array( $rules ) || array() === $rules || count( $rules ) > 2000 || array_keys( $rules ) !== range( 0, count( $rules ) - 1 ) ) {
		$errors[] = 'rules debe ser una lista de 1 a 2000 reglas';

		return $errors;
	}

	$ids    = array();
	$stress = array(
		str_repeat( 'a', 20000 ) . '!',
		str_repeat( 'a ', 10000 ) . '!',
		str_repeat( '1', 20000 ) . 'x',
		str_repeat( "'", 10000 ),
		str_repeat( '<a ', 5000 ) . '>',
		str_repeat( '../', 5000 ),
		str_repeat( "x'\"()<>;=-/*# \t", 1000 ),
		str_repeat( 'or 1=', 3000 ),
		str_repeat( 'union ', 3000 ),
	);
	$normal = array(
		'/',
		'/blog/2026/09/como-proteger-tu-web/',
		'seguridad wordpress',
		"Muy buen artículo. ¿Podríais explicar cómo se configura? Gracias.\n\nUn saludo, O'Brien.",
		'maria@example.com',
		'https://example.com/blog/',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
		'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
		'{"necessary":true,"analytics":false}',
		'Hola, me gustaría pedir presupuesto (2 unidades) para el 15/10. Teléfono: +34 600 000 000.',
		'factura-2026.pdf',
	);

	ini_set( 'pcre.backtrack_limit', '100000' );

	foreach ( $rules as $index => $rule ) {
		$label = 'regla #' . $index . ( is_array( $rule ) && isset( $rule['id'] ) && is_scalar( $rule['id'] ) ? ' (id ' . $rule['id'] . ')' : '' );

		if ( ! is_array( $rule ) ) {
			$errors[] = "$label: no es un objeto";
			continue;
		}

		foreach ( array_diff( array_keys( $rule ), AGR_RULE_KEYS ) as $key ) {
			$errors[] = "$label: campo desconocido $key";
		}

		if ( ! is_int( $rule['id'] ?? null ) || $rule['id'] < 1 || $rule['id'] > 999999 ) {
			$errors[] = "$label: id debe ser un entero entre 1 y 999999";
		} elseif ( isset( $ids[ $rule['id'] ] ) ) {
			$errors[] = "$label: id repetido";
		} else {
			$ids[ $rule['id'] ] = true;
		}

		if ( ! is_string( $rule['category'] ?? null ) || 1 !== preg_match( '/^[a-z0-9_]{1,32}$/', $rule['category'] ) ) {
			$errors[] = "$label: category no válida";
		}

		foreach ( array( 'targets' => AGR_TARGETS, 'transforms' => AGR_TRANSFORMS ) as $field => $allowed ) {
			if ( 'transforms' === $field && ! isset( $rule[ $field ] ) ) {
				continue;
			}

			$list = $rule[ $field ] ?? null;

			if ( ! is_array( $list ) || ( 'targets' === $field && array() === $list ) || array() !== array_diff( $list, $allowed ) ) {
				$errors[] = "$label: $field no válido";
			}
		}

		foreach ( array( 'fast', 'admin_exempt' ) as $field ) {
			if ( isset( $rule[ $field ] ) && ! is_bool( $rule[ $field ] ) ) {
				$errors[] = "$label: $field debe ser true o false";
			}
		}

		$pattern = $rule['pattern'] ?? null;

		if ( ! is_string( $pattern ) || strlen( $pattern ) > 4000 || 1 !== preg_match( '#^/.+/[imsxuD]*$#s', $pattern ) || false !== strpos( $pattern, '(*' ) ) {
			$errors[] = "$label: pattern debe ir entre / con modificadores imsxuD y sin verbos (*...)";
			continue;
		}

		if ( false === @preg_match( $pattern, '' ) ) {
			$errors[] = "$label: pattern no compila";
			continue;
		}

		$start = microtime( true );

		foreach ( $stress as $value ) {
			if ( false === @preg_match( $pattern, strtolower( $value ) ) || PREG_NO_ERROR !== preg_last_error() || microtime( true ) - $start > 0.05 ) {
				$errors[] = "$label: pattern demasiado lento o con retroceso excesivo";
				break;
			}
		}

		foreach ( $normal as $value ) {
			if ( 1 === preg_match( $pattern, strtolower( $value ) ) ) {
				$errors[] = "$label: coincide con un valor normal: $value";
				break;
			}
		}
	}

	return $errors;
}
