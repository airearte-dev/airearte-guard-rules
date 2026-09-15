# AirearteGuard Rules

Reglas del cortafuegos (WAF) de AirearteGuard.

Los sitios con AirearteGuard descargan una vez al día la última release por HTTPS, sólo desde GitHub, validan las
reglas (formato estricto, expresiones lentas, coincidencias con visitas normales, versión mayor que la instalada) y
sólo entonces las aplican. Si algo falla, siguen con las reglas que tenían. No se envía ningún dato del sitio.

Este repositorio sólo contiene **datos**: ninguna regla es código, y el plugin nunca ejecuta nada descargado.

> **Seguridad.** Lo que se publica aquí llega a todos los sitios. El acceso a esta cuenta de GitHub equivale a poder
> cambiar las reglas de todos ellos: mantener el 2FA con aplicación o llave física, no por SMS, y no crear tokens de
> acceso con permiso de escritura que no se necesiten.

## Estructura

| Ruta | Contenido |
|---|---|
| `packages/waf-rules.json` | Paquete de reglas del WAF |
| `tools/validate.php` | Valida el paquete |
| `.github/workflows/validate.yml` | Valida cada cambio y publica la release al subir una etiqueta |

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

- `serial`: `AAAAMMDDNN`. **Sólo puede crecer**: los sitios rechazan una versión menor o igual que la instalada.
- `id`: estable entre versiones. Publicar una regla con el id de una incluida en el plugin la sustituye (así se
  corrige un falso positivo); las reglas del plugin que no se publican siguen aplicándose.
- `targets`: `uri`, `args`, `args_names`, `cookies`, `headers`, `files`.
- `transforms`: `urldecode`, `html`, `lowercase`, `compress`, `sql_comments`, `null_bytes`, `path`.
- `pattern`: entre `/`, modificadores `imsxuD`, sin verbos `(*...)`.
- Un campo desconocido invalida el paquete entero.

## Publicar una versión

```bash
git pull
# editar packages/waf-rules.json: cambiar reglas y subir serial y released
php tools/validate.php
git commit -am "Update WAF rules"
git tag v2026091601          # la etiqueta es v + serial
git push && git push --tags
```

Actions valida el paquete, comprueba que la etiqueta coincide con `serial` y que es mayor que la versión publicada,
y crea la release con `waf-rules.json`. Los sitios la recogen en su siguiente comprobación diaria, o al pulsar
«Buscar reglas nuevas» en la pantalla del cortafuegos.

**Si una versión da problemas:** publicar cuanto antes otra con `serial` mayor que lo corrija. En un sitio concreto se
puede volver atrás desde la pantalla del cortafuegos o con `wp airguard rules rollback`.
