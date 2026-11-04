# Laboratorio 4 de Criptografía

El código está implementado y ejecutado con tus archivos reales. Se recuperó el PIN **4827** y se autenticaron las **40 transacciones**. Docker y la conexión SSH se probaron con los cuatro algoritmos de la rúbrica. Hay una captura SSH válida de **42 paquetes**.

Empieza por **[GUIA_PASO_A_PASO.md](GUIA_PASO_A_PASO.md)**: explica qué abrir, qué analizar y qué pantallazos agregar. El informe editable está en `informe/Informe_Laboratorio_4.docx`, con versión PDF y Markdown. Completa nombre, correo y sección, revisa el contenido y agrega tus capturas de Wireshark donde se indica.

## Ejecutar otra vez

Desde Terminal, con Docker Desktop abierto:

```sh
cd /Users/cris/lab-4-cripto
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/descifrar.py
.venv/bin/python -m unittest discover -s tests -v
python3 scripts/ssh_demo.py
```

`descifrar.py` genera `resultados/resultado.json`, `transacciones.csv`, `transacciones.txt`, `salt.bin` y `pin_cifrado.bin`. Verifica la correspondencia del par RSA, OAEP, los tags GCM y los campos de cada transacción. Ante un fallo devuelve código de salida 1; no escribe un nuevo conjunto de resultados. Si ya había resultados de otra ejecución, estos permanecen y deben distinguirse del intento fallido por el estado de la ejecución.

`ssh_demo.py` construye la imagen, inicia el contenedor, verifica la configuración efectiva, conecta desde el Mac, captura el tráfico y guarda una carpeta nueva en `evidencias/`. No modifica `~/.ssh`: usa claves y `known_hosts` propios en `.local/`. La clave del servidor se obtiene por Docker para fijar su identidad antes de conectar. El puerto se publica solamente en `127.0.0.1:2222`.

## Archivos

| Archivo/carpeta | Uso |
| --- | --- |
| `Dockerfile`, `compose.yaml`, `ssh/` | Servidor y configuración SSH |
| `scripts/ssh_demo.py` | Construcción, conexión y captura automáticas |
| `scripts/descifrar.py` | RSA-OAEP → PIN → Scrypt → AES-GCM |
| `tests/test_descifrar.py` | Pruebas positivas y de rechazo de datos alterados |
| `datos/` | PCAP y claves del docente, excluidos de Git |
| `resultados/` | Transacciones reales y parámetros recuperados |
| `evidencias/ssh-20261104-164221/` | Ejecución SSH verificada, con 42 paquetes |
| `evidencias/descifrado.log` | Salida completa del descifrado real |
| `informe/` | Informe y plantilla original del docente |

La carpeta `evidencias/ssh-20261104-164048/` corresponde a un primer intento cuya captura quedó vacía; **no usarla como evidencia de tráfico**. La conexión allí sí funcionó, pero la ejecución válida para el informe es `ssh-20261104-164221`.

## Alcance del lector PCAP

El script se ajusta al formato comprobado del docente: un registro completo por payload TCP, un único paquete RSA y 40 paquetes AESGCM del mismo flujo. También lee payloads UDP con el mismo formato. No es un reensamblador general de TCP: rechaza fragmentos desconocidos del flujo, registros truncados y varias sesiones, y omite retransmisiones TCP idénticas. No debe aplicarse sin adaptación a otros protocolos o capturas con mensajes repartidos entre segmentos.

## Detener y regenerar el informe

```sh
docker compose down
# Solo si quieres reconstruir DOCX/PDF desde el Markdown:
.venv/bin/python -m pip install -r requirements-informe.txt
.venv/bin/python scripts/exportar_informe.py
```

El volumen conserva la clave de host para futuras ejecuciones. El generador de documentos sobrescribe las versiones DOCX/PDF: si ya agregaste pantallazos en Word, conserva una copia antes de regenerarlas. Los secretos de laboratorio y las evidencias se excluyen de Git; para entregar, adjunta explícitamente los archivos que pide el docente.
