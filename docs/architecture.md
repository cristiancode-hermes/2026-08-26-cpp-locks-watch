# locks-watch — Architecture

## Flujo

```
/proc/locks ─────► parse_locks_file() ──► std::vector<FileLock>
                       │                         │
                       │                         ▼
                       │                 resolve_procs() (pid→comm)
                       │                         │
                       │               ┌─────────┴─────────┐
                       │               ▼                  ▼
                       │         render_snapshot()   render_json()
                       │               │
                       ▼               ▼
                  filtros (type/access/pid/byte-range) → watch delta
```

## Decisiones técnicas

- **Monolítico stdlib-only**: un solo TU, `g++ -std=c++23` directo, zero dependencias.
- **Paleta ANSI mutable**: `--no-color` vacía las strings de color en runtime
  (no `constexpr`) — afecta por igual a selftest, watch y snapshot.
- **Formato kernel**: cada línea es `id: TYPE MODE ACCESS PID DEV:INODE START END`.
  `EOF` en la última columna significa "fin de archivo" (lock de todo el fichero);
  un número es un offset finito. `0 0` explicito NO es EOF (bloquea el byte 0).
  El sentinel interno es `end = -1` para EOF — así `end == 0` sigue siendo un
  byte real y `is_eof()` es inequívoco.
- **Inode**: la columna `DEV:INODE` llega como un único token (`08:01:7424305`);
  se parte por la ÚLTIMA `:` (el device es `MAJ:MIN`, el inode es lo restante).
- **parse_hex con detección de base**: inodes como `7424305` (todo dígitos) se
  parsean en decimal; solo si hay letras (`1ce`) se usa base 16.
- **Dumps tolerantes**: `--file` salta líneas `#` y recorta anotaciones tras `#`,
  así los dumps de demo se pueden documentar inline.
- **pid→comm**: lectura directa de `/proc/<pid>/comm`; si el proceso murió
  entre el parseo y la resolución, se omite sin error.
- **Demo buffer flush**: `demo_load_file()` escribe el fichero demo en un scope
  `{}` que cierra el ofstream ANTES de llamar a `parse_locks_file()` — sin el
  cierre explícito, el parser leía un fichero vacío (buffer sin flush).

## Riesgos conocidos

- `/proc/locks` no tiene header (a diferencia de `/proc/net/*`) — el parser no
  salta ninguna línea de cabecera, solo comentarios.
- Los locks cambian constantemente en hosts con mucha E/S — el modo watch
  (`--watch N`) muestra deltas idénticos si el host está quieto (normal).
- En contenedores Docker el `/proc/locks` refleja solo el namespace del
  contenedor: puede mostrar 0 locks aunque el host tenga cientos — usar
  `--demo` para verificar el render.