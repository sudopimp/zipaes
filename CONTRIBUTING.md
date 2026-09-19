# Cómo colaborar

Gracias por el interés. Este proyecto es chico y prefiere pocos cambios bien hechos.

## Antes de abrir un issue

- Corré `zipaes selftest` y `zipaes selftest --ae1`. Si fallan, el problema está en el
  entorno o en el propio paquete, y el informe va a ser mucho más útil con esa salida.
- Corré `zipaes info tu-archivo.zip`. Muchos casos se explican solos con esa salida (es
  ZipCrypto, es AE-1, no está cifrado).
- **No subas archivos reales ni contraseñas.** Para reproducir un problema alcanza con un
  archivo generado con `zipaes.testkit`, como hacen las pruebas del repositorio.

## Entorno de desarrollo

```bash
git clone https://github.com/sudopimp/zipaes
cd zipaes
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make check          # lint + formato + pruebas
pre-commit install  # opcional: corre todo antes de cada commit
```

## Reglas para los pull requests

1. **Un cambio, un motivo.** Nada de reformatear archivos que no tocaste.
2. **Con pruebas.** Todo cambio de comportamiento necesita un caso que lo cubra. Si es un
   arreglo, la prueba debe fallar antes del arreglo.
3. **Sin dependencias nuevas** salvo que sean imprescindibles y estén bien justificadas. El
   paquete sólo depende de `cryptography` a propósito.
4. **En español** para la documentación y los mensajes de la interfaz; el código sigue el
   estilo de `ruff`.
5. **Compatibilidad.** El paquete soporta Python 3.10 o superior.

## Áreas donde hace falta ayuda

- **Soporte de ZIP64** (>4 GB): hoy se detecta e informa, pero el parseo completo está
  pendiente. Archivos multi-volumen, también.
- **Emisión del hash `$pkzip2$`** para atacar ZipCrypto con hashcat `--mode 17200` desde
  acá. Hoy se resuelve con el backend propio, que para este formato alcanza, pero
  completarlo cerraría el círculo.
- **Verificación con archivos reales de más herramientas**: hay interoperabilidad probada
  contra 7-Zip (AES) e Info-ZIP (ZipCrypto). Faltan WinZip, WinRAR y las bibliotecas de
  otros lenguajes (el crate `zip` de Rust, por ejemplo).
- **Pruebas de `fuzz` con `atheris` o `hypothesis`**, para pasar del fuzzing determinista
  actual a cobertura guiada.
- **Rendimiento del backend propio**: hoy es Python puro; un kernel en C o una extensión
  con `cffi` lo acercarían a lo que hace hashcat sin depender de la GPU.

## Estilo de los mensajes de commit

```
tipo: descripción breve en imperativo

Cuerpo opcional explicando el porqué, no el qué.
```

Tipos: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.

## Licencia de las contribuciones

Al enviar un pull request aceptás que tu aporte se distribuya bajo la licencia MIT del
proyecto.