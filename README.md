# sysmon (core)

Librairie C (statique) + binaire CLI pour monitorer des métriques système via des modules.

## Build

```sh
cmake -S . -B build
cmake --build build -j
```

## CLI (test)

```sh
./build/sysmon-cli -n 5
./build/sysmon-cli --json -n 1
./build/sysmon-cli -c sysmon.ini
```

## Configuration (.ini)

- Section globale: `[sysmon]`
  - `interval_ms`: utilisé par `sysmon-cli` pour l’intervalle d’affichage
- Modules: `[module.<nom>]`
  - `enabled`: `1/0`, `true/false`, `yes/no`, `on/off`
  - `refresh_ms`: fréquence de rafraîchissement propre au module (les valeurs sont mises en cache entre 2 refresh)
  - `interface`: (module `network`) interface réseau (vide = auto)
  - `include_loopback`: (module `network`) `1/0` pour autoriser `lo0`/`lo`
  - `path`: (module `storage`) chemin de montage à sonder (par défaut `/`)

Exemple: `sysmon.ini`

## Modules intégrés

- `cpu`: `cpu.usage_percent`, `cpu.core_count`
- `ram`: `ram.total_bytes`, `ram.used_bytes`, `ram.free_bytes`, `ram.used_percent`
- `battery`: `battery.percent`, `battery.is_charging`, `battery.status` (désactivé automatiquement si non supporté)
- `network`: `network.interface`, `network.rx_bytes`, `network.tx_bytes`, `network.rx_bytes_per_sec`, `network.tx_bytes_per_sec`
- `storage`: `storage.path`, `storage.total_bytes`, `storage.used_bytes`, `storage.free_bytes`, `storage.available_bytes`, `storage.used_percent`
