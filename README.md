# AirearteGuard Rules

Reglas del cortafuegos (WAF) de AirearteGuard, publicadas y firmadas.

Los sitios con AirearteGuard descargan una vez al día la última release, comprueban la firma Ed25519 con las claves
incluidas en el plugin, validan las reglas (formato estricto, expresiones lentas, coincidencias con visitas normales)
y sólo entonces las aplican. Si algo falla, siguen con las reglas que tenían. No se envía ningún dato del sitio.

Este repositorio sólo contiene **datos**: ninguna regla es código, y el plugin nunca ejecuta nada descargado.

## Estructura

| Ruta | Contenido |
|---|---|
| `packages/waf-rules.json` | Paquete de reglas del WAF |
| `keys/<id>.pub` | Claves públicas aceptadas |
| `tools/validate.php` | Valida el paquete |
| `tools/generate-keys.php` | Genera un par de claves (sólo en el equipo del responsable) |
| `tools/sign.php` | Valida y firma el paquete en `dist/` |
| `tools/verify.php` | Verifica un paquete firmado |
| `.github/workflows/validate.yml` | Valida en cada cambio y verifica lo subido a cada release |

## Formato

```json
{
  "format": 1,
  "kind": "waf-rules",
  "serial": 2026091501,
  "released": "2026-09-15",
  "min_plugin": "0.2.0",
  "notes": "Opcional",
  "rules": [
    {
      "id": 1001,
      "category": "sqli",
      "targets": ["args", "cookies", "uri", "headers"],
      "transforms": ["urldecode", "lowercase"],
      "pattern": "/\\bunion\\b.../",
      "fast": true,
      "admin_exempt": false,
      "description": "Opcional"
    }
  ]
}
```

- `serial`: `AAAAMMDDNN`. **Sólo puede crecer**: los sitios rechazan una versión menor que la instalada.
- `id`: estable entre versiones. Publicar una regla con el id de una incluida en el plugin la sustituye (así se
  corrige un falso positivo); las reglas del plugin que no se publican siguen aplicándose.
- `targets`: `uri`, `args`, `args_names`, `cookies`, `headers`, `files`.
- `transforms`: `urldecode`, `html`, `lowercase`, `compress`, `sql_comments`, `null_bytes`, `path`.
- `pattern`: entre `/`, modificadores `imsxuD`, sin verbos `(*...)`.
- Un campo desconocido invalida el paquete entero.

## Publicar una versión

En el equipo del responsable de firmar:

```bash
git pull
# editar packages/waf-rules.json y subir serial y released
php tools/validate.php
git commit -am "Update WAF rules" && git push     # Actions valida
php tools/sign.php -                              # pegar la clave privada desde el gestor de contraseñas
php tools/verify.php
```

Crear la release con la etiqueta `v<serial>` y adjuntar **exactamente** `dist/waf-rules.json` y
`dist/waf-rules.json.sig`, sin editarlos. Actions vuelve a verificar lo subido.

Si una versión publicada da problemas: publicar cuanto antes una versión con `serial` mayor que lo corrija. En un
sitio concreto se puede volver atrás desde la pantalla del cortafuegos o con `wp airguard rules rollback`.

## Claves

- Dos pares: **principal** y **reserva**, cada uno custodiado por una persona distinta.
- Generar cada par con `php tools/generate-keys.php <ruta-fuera-del-repositorio>`, guardar la clave privada en el
  gestor de contraseñas y borrar el fichero.
- Las claves privadas nunca se guardan en este repositorio, en un servidor, en GitHub (ni como secreto de Actions)
  ni en el correo.
- **Clave comprometida:** publicar una versión del plugin sin esa clave, firmar con la de reserva y generar un par
  nuevo que sustituya al retirado.
