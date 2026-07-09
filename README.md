# Wazuh Indexer Forensic Exporter

Exportador forense en Python para **Wazuh Indexer / OpenSearch**. Permite extraer eventos históricos por mes en formato `NDJSON.GZ`, generando evidencias de integridad como `manifest.json`, `sha256.txt` y `backup.log`.

Está pensado para auditoría, análisis forense, continuidad operacional y respaldos temporales antes de eliminar índices antiguos del Wazuh Indexer.

## ¿Para qué sirve?

Este script permite respaldar eventos de Wazuh de forma controlada y verificable.

Casos de uso comunes:

- Exportar eventos `wazuh-alerts-*` de un mes específico.
- Respaldar información antes de liberar espacio en el Indexer.
- Conservar evidencia para auditoría o investigación forense.
- Validar cantidad esperada versus cantidad exportada.
- Generar hashes SHA256 para verificar integridad.

## Características

- Modo interactivo.
- Compatible con Wazuh Indexer / OpenSearch.
- Soporta certificado admin local o usuario/password.
- Exporta `wazuh-alerts`, `wazuh-archives`, ambos o un patrón manual.
- Detección automática de campo temporal: `timestamp`, `@timestamp`, `event.created` o manual.
- Exportación paralela por slices.
- Validación previa de espacio disponible.
- Barra de progreso, velocidad y ETA.
- Genera `backup.log` dentro de la carpeta del respaldo.
- Genera `manifest.json`.
- Genera `sha256.txt`.
- ZIP final opcional.
- No borra eventos del Indexer.
- No modifica configuración.
- No elimina respaldos locales automáticamente.

## Requisitos

- Python 3.
- Acceso a la **API HTTPS del Wazuh Indexer/OpenSearch**, normalmente en el puerto `9200`.
  - Aunque el script se ejecuta por CLI, la extracción se realiza consultando la API HTTPS del Indexer.
  - No requiere acceso al Wazuh Dashboard.
  - Si ejecutas el script desde el propio Indexer, puedes usar `https://127.0.0.1:9200`.
  - Si lo ejecutas desde otro servidor, ese servidor debe tener conectividad hacia el puerto `9200` del Indexer.
- Certificados admin del Wazuh Indexer o usuario/password con permisos de lectura sobre los índices.
- Espacio suficiente en disco para almacenar el respaldo temporal o final.

En Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3
```

## Instalación rápida

Clonar el repositorio:

```bash
git clone https://github.com/j1n-kazama/wazuh_idx_bkp.git
cd wazuh_idx_bkp
chmod +x wazuh_indexer_forensic_exporter_generic.py
```

Opcionalmente, puedes dejarlo en una ruta operativa:

```bash
sudo mkdir -p /opt/wazuh-tools
sudo cp wazuh_indexer_forensic_exporter_generic.py /opt/wazuh-tools/
sudo chmod 700 /opt/wazuh-tools/wazuh_indexer_forensic_exporter_generic.py
```

## Uso rápido

Ejecutar:

```bash
sudo python3 wazuh_indexer_forensic_exporter_generic.py
```

O si lo copiaste a `/opt/wazuh-tools`:

```bash
sudo python3 /opt/wazuh-tools/wazuh_indexer_forensic_exporter_generic.py
```

## Valores recomendados

Si ejecutas desde el propio Wazuh Indexer:

```text
IP/host del Wazuh Indexer: 127.0.0.1
Puerto HTTPS: 9200
Tipo de datos: 1) Solo alerts
Campo temporal: auto
Slices: 4
Batch size: 10000
Scroll: 10m
Crear ZIP final: No, si tienes poco espacio
Autenticación: 1) Certificado admin local
```

## Certificados Wazuh

Rutas típicas de certificados Wazuh:

```text
/etc/wazuh-indexer/certs/admin.pem
/etc/wazuh-indexer/certs/admin-key.pem
/etc/wazuh-indexer/certs/root-ca.pem
```

Cuando el script pregunte por estas rutas, se recomienda presionar **ENTER** para usar los valores por defecto, salvo que tu instalación tenga certificados personalizados o ubicados en otra ruta.

Ejemplo:

```text
Ruta admin.pem [/etc/wazuh-indexer/certs/admin.pem]: ENTER
Ruta admin-key.pem [/etc/wazuh-indexer/certs/admin-key.pem]: ENTER
Ruta root-ca.pem [/etc/wazuh-indexer/certs/root-ca.pem]: ENTER
```

## Cálculo de espacio requerido

Antes de exportar, el script calcula el espacio requerido para evitar llenar el disco.

Si **NO** se crea ZIP final:

```text
espacio requerido = store.size del mes × factor de seguridad + margen libre mínimo
```

Si **SÍ** se crea ZIP final:

```text
espacio requerido = store.size del mes × factor de seguridad × 2 + margen libre mínimo
```

Se multiplica por `2` porque se mantiene la carpeta exportada y además se crea el ZIP final.

Ejemplo:

```text
store.size del mes: 1.37 GB
factor de seguridad: 1.20
ZIP final: NO
margen libre mínimo: 20 GB

export estimado = 1.37 × 1.20 = 1.65 GB
espacio requerido = 1.65 + 20 = 21.65 GB
```

Si el espacio libre actual es mayor al requerido, la exportación puede continuar.

## Salida generada

El script crea una carpeta similar a:

```text
backups_wazuh_eventos_julio2026/
├── backup.log
├── wazuh-eventos-julio2026_slice0_of4_<timestamp>.ndjson.gz
├── wazuh-eventos-julio2026_slice1_of4_<timestamp>.ndjson.gz
├── wazuh-eventos-julio2026_slice2_of4_<timestamp>.ndjson.gz
├── wazuh-eventos-julio2026_slice3_of4_<timestamp>.ndjson.gz
├── wazuh-eventos-julio2026_manifest_<timestamp>.json
├── wazuh-eventos-julio2026_sha256_<timestamp>.txt
└── *_summary.json
```

## Validar respaldo

Entrar a la carpeta generada:

```bash
cd backups_wazuh_eventos_julio2026
```

Validar integridad:

```bash
sha256sum -c wazuh-eventos-*_sha256_*.txt
```

Validar archivos comprimidos:

```bash
find . -name "*.ndjson.gz" -exec gzip -t {} \;
```

Revisar manifest:

```bash
grep -E '"expected_count"|"total_exported"|"complete"' wazuh-eventos-*_manifest_*.json
```

Resultado esperado:

```text
"complete": true
expected_count = total_exported
```

> Recomendación: para respaldos definitivos, exporta meses cerrados. Si exportas el mes actual mientras el Indexer sigue recibiendo eventos, puede existir una pequeña diferencia entre `expected_count` y `total_exported`.

## POC de ejemplo

Ejemplo de ejecución:

```text
IP/host del Wazuh Indexer [127.0.0.1]: 172.31.100.10
Puerto HTTPS del Wazuh Indexer [9200]: 9200
Mes a respaldar en formato YYYY-MM [2026-07]: 2026-07
Selecciona opcion [1]: 1
Campo temporal [auto]: auto
Carpeta base donde guardar el respaldo [/home/user]: /home/user
Cantidad de slices paralelos [4]: 4
Tamaño de lote por scroll [10000]: 10000
Tiempo de scroll [10m]: 10m
Espacio libre mínimo a conservar en GB [80]: 20
Factor de seguridad sobre store.size [1.20]: 1.20
¿Crear ZIP final además de dejar la carpeta? [S/n]: n
Selecciona opcion [1]: 1
Ruta admin.pem [/etc/wazuh-indexer/certs/admin.pem]: ENTER
Ruta admin-key.pem [/etc/wazuh-indexer/certs/admin-key.pem]: ENTER
Ruta root-ca.pem [/etc/wazuh-indexer/certs/root-ca.pem]: ENTER
```

Validación de ejemplo:

```text
AUTH_OK=CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US
Indices encontrados: 9
Docs por _cat: 937.491
Store size aprox: 1.37 GB
TIME_FIELD_AUTO=timestamp
Eventos esperados: 937.794

Modo cálculo: carpeta exportada + margen libre
store.size del mes: 1.37 GB
factor seguridad: 1.20x
export estimado: 1.65 GB
crear ZIP final conservando carpeta: NO
margen libre final requerido: 20 GB
espacio libre actual: 1191.39 GB
espacio requerido total: 21.65 GB

OK: espacio suficiente para exportar con margen de seguridad.
```

Progreso de ejemplo:

```text
[███████████████████████████████████] 100.00% | 937.795/937.794 eventos | 4.770 ev/s | ETA 00:00:00
```

> Nota: en este ejemplo se exportó un mes en curso. Si Wazuh sigue recibiendo eventos durante la exportación, puede existir una diferencia mínima entre `expected_count` y `total_exported`. Para evidencia final, se recomienda exportar meses ya cerrados.

## Recomendaciones

- Ejecutar en ventana de baja carga.
- Usar `wazuh-alerts-*` para auditoría SOC y análisis forense operativo.
- Evitar ZIP si el disco tiene poco espacio, porque duplica temporalmente el consumo.
- Ajustar el margen mínimo libre según el tamaño del Indexer.
- Para respaldos definitivos, exportar meses cerrados.
- No eliminar índices antiguos hasta confirmar que el respaldo quedó completo y validado.

## Seguridad operacional

Este script es de solo lectura sobre Wazuh Indexer:

```text
No elimina índices.
No modifica configuración.
No borra eventos.
No elimina respaldos existentes automáticamente.
```

## Licencia

MIT License.
