# AirearteGuard Rules

Reglas del cortafuegos (WAF) y firmas de malware de AirearteGuard.

Los sitios con AirearteGuard descargan una vez al día la última release por HTTPS, sólo desde GitHub, validan lo
descargado (formato estricto, expresiones lentas, coincidencias con visitas normales o con código legítimo, versión
mayor que la instalada) y sólo entonces lo aplican. Si algo falla, siguen con lo que tenían. No se envía ningún dato
del sitio.

Este repositorio sólo contiene **datos**: ninguna regla es código, y el plugin nunca ejecuta nada descargado.

> **Seguridad.** Lo que se publica aquí llega a todos los sitios. El acceso a esta cuenta de GitHub equivale a poder
> cambiar las reglas de todos ellos: mantener el 2FA con aplicación o llave física, no por SMS, y no crear tokens de
> acceso con permiso de escritura que no se necesiten.

## Estructura

| Ruta | Contenido |
|---|---|
| `packages/waf-rules.json` | Paquete de reglas del WAF |
| `packages/malware-signatures.json` | Paquete de firmas de malware |
| `tools/validate.php` | Valida los dos paquetes |
| `tools/publish-check.php` | Comprueba que una etiqueta se puede publicar |
| `.github/workflows/validate.yml` | Valida cada cambio y publica la release al subir una etiqueta |

## Formato de las reglas del WAF

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

- `serial`: `AAAAMMDDNN`. **Sólo puede crecer**: los sitios rechazan una versión menor o igual que la instalada.
- `id`: estable entre versiones. Publicar una regla con el id de una incluida en el plugin la sustituye (así se
  corrige un falso positivo); las reglas del plugin que no se publican siguen aplicándose.
- `targets`: `uri`, `args`, `args_names`, `cookies`, `headers`, `files`.
- `transforms`: `urldecode`, `html`, `lowercase`, `compress`, `sql_comments`, `null_bytes`, `path`.
- `pattern`: entre `/`, modificadores `imsxuD`, sin verbos `(*...)`.
- Un campo desconocido invalida el paquete entero.

## Formato de las firmas de malware

```json
{
  "format": 1,
  "kind": "malware-signatures",
  "serial": 2026091601,
  "released": "2026-09-16",
  "min_plugin": "0.2.0",
  "notes": "Opcional",
  "signatures": [
    {
      "id": 1001,
      "name": "WSO web shell",
      "type": "webshell",
      "level": "confirmed",
      "targets": ["php"],
      "fast": ["filesman"],
      "pattern": "/\\$default_action\\s*=\\s*['\"]FilesMan['\"]/i"
    }
  ]
}
```

- `level`: `confirmed` (familia de malware conocida), `evidence` (construcción que el código legítimo no usa) o
  `suspicion` (ofuscación que algún producto comercial también usa). El plugin lo muestra como certeza.
- `type`: `webshell`, `backdoor`, `dropper`, `obfuscation`, `injection`, `redirect`, `spam`.
- `targets`: `php`, `js`, `html` (el contenido de la base de datos se analiza como `html`).
- `fast`: literales en minúsculas. La expresión sólo se evalúa si el contenido contiene alguno, y por eso son
  obligatorios: sin ellos cada fichero del sitio pagaría la expresión entera.
- `pattern`: entre `/`, modificadores `imsxuD`, sin verbos `(*...)`, con repeticiones acotadas.
- `name` se muestra tal cual, en inglés, como el nombre que dan los antivirus.
- Una sola firma inválida o lenta invalida el paquete entero.

La herramienta del plugin genera el paquete a partir de las firmas que incluye:

```bash
php tools/export-signatures.php 2026091601 2026-09-16 > packages/malware-signatures.json
```

## Publicar una versión

Cada release contiene **los dos paquetes**, cada uno con su propia versión: los sitios descargan siempre de la última
release y sólo instalan lo que sea más nuevo que lo que tienen.

```bash
git pull
# editar el paquete que cambie y subir su serial y su released
php tools/validate.php
php tools/publish-check.php v2026091601
git commit -am "Update malware signatures"
git tag v2026091601          # la etiqueta es v + la versión de esta publicación
git push && git push --tags
```

Actions valida los dos paquetes, comprueba que ninguno supera la etiqueta, que ninguno baja de la versión ya publicada
y que al menos uno trae algo nuevo, y crea la release con los dos ficheros. Los sitios la recogen en su siguiente
comprobación diaria, o al pulsar «Buscar reglas nuevas» en la pantalla del cortafuegos y «Buscar firmas nuevas» en la
de hallazgos.

**Si una versión da problemas:** publicar cuanto antes otra con `serial` mayor que lo corrija. En un sitio concreto se
puede volver atrás desde la pantalla correspondiente o con `wp airguard rules rollback` y `wp airguard signatures
rollback`.
