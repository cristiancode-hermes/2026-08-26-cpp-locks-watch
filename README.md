# locks-watch

Monitor de locks de archivos del kernel Linux en tiempo real (C++23, zero deps).

Lee `/proc/locks` y muestra cada lock del sistema: tipo (`FLOCK`, `POSIX`,
`OFDLCK`), modo (`ADVISORY` / `MANDATORY`), acceso (`READ` / `WRITE`), PID
propietario, dispositivo `MAJ:MIN`, inode, y rango de bytes bloqueado
(`0-EOF` = archivo completo — `128` = byte 128 — `1024-2048` = rango finito).
Resuelve el nombre del proceso vía `/proc/<pid>/comm`. Útil para auditar
por qué un fichero está bloqueado, detectar locks MANDATORY raros o
contención entre procesos (p. ej. DB + web + cron sobre los mismos datos).

## Features

- **Parse de `/proc/locks`**: formato estándar del kernel, 1 línea por lock
- **Clasificación**: FLOCK (flock(2)), POSIX (fcntl F_SETLK/F_SETLKW), OFDLCK (open file description locks)
- **Modo MANDATORY**: `--mandatory` filtra solo locks obligatorios (los raros)
- **Rangos de bytes**: punto final (`128`), rango (`1024-2048`) o archivo completo (`0-EOF`),
  con `--byte-range` para quedarte solo con los finitos
- **Resolución PID → proceso**: `/proc/<pid>/comm`, tolerante a procesos muertos
- **Modo watch (`--watch N`)**: refresh periódico con deltas (locks nuevos/liberados)
- **Salida JSON (`--json`)**: `summary` + array `locks` validable con `python -m json.tool`
- **Demo mode (`--demo`)**: host sintético DB + web + browser con 32 locks
- **Filtros**: `--type FLOCK|POSIX|OFDLCK`, `--access READ|WRITE`, `--pid N`, `--top N`, `--sort id|pid|inode`
- **`--file`**: parsea un dump (tolera comentarios `#` y anotaciones)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 42 checks (parser, EOF, filtros, demo, JSON, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o locks-watch
```

## Usage

```bash
# Snapshot único (host real)
./locks-watch

# Modo watch (cada 2s) con deltas entre snapshots
./locks-watch --watch 2

# Solo locks flock(2)
./locks-watch --type FLOCK

# Solo escrituras
./locks-watch --access WRITE

# Solo locks con rango de bytes finito
./locks-watch --byte-range

# Locks de un proceso concreto
./locks-watch --pid 3315

# JSON
./locks-watch --json

# Demo (host DB + web + browser sintético)
./locks-watch --demo

# Parsear un dump con comentarios
./locks-watch --file sample-locks.table --no-color

# Sin colores
./locks-watch --no-color

# Auto-tests
./locks-watch --selftest
```

## Data Source

`/proc/locks` — tabla de locks del kernel:

| Campo | Ejemplo | Significado |
|-------|---------|-------------|
| id | `1:` | identificador del lock |
| type | `FLOCK` | `FLOCK` (flock(2)), `POSIX` (fcntl), `OFDLCK` |
| mode | `ADVISORY` | `ADVISORY` (cooperativo) o `MANDATORY` (forzado por el kernel) |
| access | `WRITE` | `READ` o `WRITE` |
| pid | `1129` | proceso propietario |
| dev:inode | `08:01:7424305` | dispositivo `MAJ:MIN` + inode del fichero |
| start | `0` | primer byte bloqueado (offset) |
| end | `EOF` | último byte: `EOF` = fin de archivo, número = offset finito |

Nota: `MANDATORY` solo existe si el filesystem se monta con `mand` y el fichero
tiene `setgid` sin `group-execute`. En la mayoría de hosts modernos el contador
es 0 — el flag existe para detectar configuraciones raras.

## Example Output

```
  Linux File-Lock Monitor  /proc/locks
  Source: demo (synthetic)  ·  Snapshot: 1787714029
  ----------------------------------------------------------------------------

  32 locks   6 FLOCK   26 POSIX   11 read   21 write   0 mandatory   10 byte-range
  pids: 22

  ID    TYPE    MODE      ACCESS  PID   DEV       INODE       RANGE
  ----------------------------------------------------------------------------
  1    FLOCK  ADVISORY   WRITE   4132 postgres  08:01  9310177  0-EOF
  2    POSIX  ADVISORY   READ   4132 postgres  08:01  9310177  128
  3    POSIX  ADVISORY   READ   4132 postgres  08:01  9310177  1073741826-1073742335
  4    POSIX  ADVISORY   WRITE   5133 nginx  00:33  1022411  0-EOF
  ...
```

## Selftest

```bash
./locks-watch --selftest   # 42 checks, exit 0 = todo OK
```

Zero dependencias: solo la stdlib de C++23 y `g++ -std=c++23`.