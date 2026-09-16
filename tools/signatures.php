<?php
/**
 * Validación del paquete de firmas de malware.
 *
 * Debe coincidir con el plugin (AirearteGuard\Malware\Signatures y SignaturePackage). Si cambia allí, cambia aquí.
 */

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

const AGR_SIG_KIND         = 'malware-signatures';
const AGR_SIG_PACKAGE      = AGR_ROOT . '/packages/malware-signatures.json';
const AGR_SIG_MAX_BYTES    = 524288;
const AGR_SIG_PACKAGE_KEYS = array( 'format', 'kind', 'serial', 'released', 'min_plugin', 'notes', 'signatures' );
const AGR_SIG_KEYS         = array( 'id', 'name', 'type', 'level', 'targets', 'fast', 'pattern' );
const AGR_SIG_TYPES        = array( 'webshell', 'backdoor', 'dropper', 'obfuscation', 'injection', 'redirect', 'spam' );
const AGR_SIG_LEVELS       = array( 'confirmed', 'evidence', 'suspicion' );
const AGR_SIG_TARGETS      = array( 'php', 'js', 'html' );

/**
 * Valida un paquete de firmas con las mismas reglas que el plugin.
 *
 * @return string[] Errores.
 */
function agr_validate_signatures( string $content ): array {
	$errors = array();

	if ( '' === $content || strlen( $content ) > AGR_SIG_MAX_BYTES ) {
		return array( 'Tamaño fuera de límites (máximo 512 KB).' );
	}

	$data = json_decode( $content, true, 32 );

	if ( ! is_array( $data ) ) {
		return array( 'No es JSON válido: ' . json_last_error_msg() );
	}

	foreach ( array_diff( array_keys( $data ), AGR_SIG_PACKAGE_KEYS ) as $key ) {
		$errors[] = "Campo desconocido en el paquete: $key";
	}

	if ( 1 !== ( $data['format'] ?? null ) ) {
		$errors[] = 'format debe ser 1';
	}

	if ( AGR_SIG_KIND !== ( $data['kind'] ?? null ) ) {
		$errors[] = 'kind debe ser ' . AGR_SIG_KIND;
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

	$signatures = $data['signatures'] ?? null;

	if ( ! is_array( $signatures ) || array() === $signatures || count( $signatures ) > 2000 || array_keys( $signatures ) !== range( 0, count( $signatures ) - 1 ) ) {
		$errors[] = 'signatures debe ser una lista de 1 a 2000 firmas';

		return $errors;
	}

	// Contenidos que provocan retroceso sin llegar a coincidir, como los del plugin.
	$stress = array(
		str_repeat( 'a', 20000 ),
		str_repeat( 'a', 40 ) . '!',
		str_repeat( 'a', 5000 ) . '!',
		str_repeat( ' ', 5000 ) . '!',
		str_repeat( ' ', 20000 ) . 'eval(',
		'eval(' . str_repeat( 'base64_decode( ', 400 ) . '"' . str_repeat( 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo', 300 ),
		str_repeat( '$_POST[', 2000 ),
		str_repeat( 'chr(101).', 2000 ) . 'x',
		str_repeat( '\\x6', 5000 ),
		str_repeat( 'String.fromCharCode(104,', 500 ),
		'preg_replace("' . str_repeat( '/', 5000 ),
		str_repeat( '%3', 8000 ),
		str_repeat( "<?php\n\$a = \$_GET['a'];\n", 500 ),
	);

	// Código legítimo que ninguna firma puede señalar.
	$normal = array(
		'<?php $data = base64_decode( $_POST["data"] ); update_option( "x", sanitize_text_field( $data ) );',
		'<?php exec( "convert " . escapeshellarg( $file ) . " out.png" );',
		'<?php eval( "?>" . $template );',
		'<?php move_uploaded_file( $_FILES["f"]["tmp_name"], $dir . "/" . wp_unique_filename( $dir, $name ) );',
		'<?php include __DIR__ . "/partials/logo.php";',
		'<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>',
		'function t(e){return String.fromCharCode(e)}var s=atob(data);',
		'<?php $str = "\\x1b[31m";',
	);

	ini_set( 'pcre.backtrack_limit', '100000' );

	$ids = array();

	foreach ( $signatures as $index => $signature ) {
		$label = 'firma #' . $index . ( is_array( $signature ) && isset( $signature['id'] ) && is_scalar( $signature['id'] ) ? ' (id ' . $signature['id'] . ')' : '' );

		if ( ! is_array( $signature ) ) {
			$errors[] = "$label: no es un objeto";
			continue;
		}

		foreach ( array_diff( array_keys( $signature ), AGR_SIG_KEYS ) as $key ) {
			$errors[] = "$label: campo desconocido $key";
		}

		if ( ! is_int( $signature['id'] ?? null ) || $signature['id'] < 1 || $signature['id'] > 999999 ) {
			$errors[] = "$label: id debe ser un entero entre 1 y 999999";
		} elseif ( isset( $ids[ $signature['id'] ] ) ) {
			$errors[] = "$label: id repetido";
		} else {
			$ids[ $signature['id'] ] = true;
		}

		if ( ! is_string( $signature['name'] ?? null ) || '' === trim( $signature['name'] ) || strlen( $signature['name'] ) > 120 || 1 === preg_match( '/[\x00-\x1F\x7F<>]/', $signature['name'] ) ) {
			$errors[] = "$label: name debe ser un texto corto sin marcado";
		}

		if ( ! in_array( $signature['type'] ?? null, AGR_SIG_TYPES, true ) ) {
			$errors[] = "$label: type no válido";
		}

		if ( ! in_array( $signature['level'] ?? null, AGR_SIG_LEVELS, true ) ) {
			$errors[] = "$label: level debe ser confirmed, evidence o suspicion";
		}

		$targets = $signature['targets'] ?? null;

		if ( ! is_array( $targets ) || array() === $targets || array() !== array_diff( $targets, AGR_SIG_TARGETS ) ) {
			$errors[] = "$label: targets no válido";
		}

		$fast = $signature['fast'] ?? null;

		if ( ! is_array( $fast ) || array() === $fast || count( $fast ) > 10 ) {
			$errors[] = "$label: fast debe ser una lista de 1 a 10 literales";
		} else {
			foreach ( $fast as $literal ) {
				if ( ! is_string( $literal ) || strlen( $literal ) < 2 || strlen( $literal ) > 40 || strtolower( $literal ) !== $literal ) {
					$errors[] = "$label: literal rápido no válido (2 a 40 caracteres, en minúsculas)";
					break;
				}
			}
		}

		$pattern = $signature['pattern'] ?? null;

		if ( ! is_string( $pattern ) || strlen( $pattern ) > 2000 || 1 !== preg_match( '#^/.+/[imsxuD]*$#s', $pattern ) || false !== strpos( $pattern, '(*' ) ) {
			$errors[] = "$label: pattern debe ir entre / con modificadores imsxuD y sin verbos (*...)";
			continue;
		}

		if ( false === @preg_match( $pattern, '' ) ) {
			$errors[] = "$label: pattern no compila";
			continue;
		}

		$start = microtime( true );

		foreach ( $stress as $value ) {
			if ( false === @preg_match( $pattern, $value ) || PREG_NO_ERROR !== preg_last_error() || microtime( true ) - $start > 0.05 ) {
				$errors[] = "$label: pattern demasiado lento o con retroceso excesivo";
				break;
			}
		}

		foreach ( $normal as $value ) {
			if ( 1 === preg_match( $pattern, $value ) ) {
				$errors[] = "$label: coincide con código legítimo: " . substr( $value, 0, 60 );
				break;
			}
		}
	}

	return $errors;
}
