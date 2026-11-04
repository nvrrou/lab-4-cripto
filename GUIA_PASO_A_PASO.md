# Qué debes hacer y con qué aplicación

## 1. Qué ya está hecho

- Imagen Docker construida y servidor SSH probado.
- Negociación real de `curve25519-sha256`, `aes256-ctr`, `hmac-sha2-256` y `ssh-ed25519`.
- Conexión desde el Mac como `alumno`, con salida `LAB4_SSH_OK`.
- Captura SSH real de 42 paquetes, sin paquetes descartados por el kernel.
- Identificación del paquete RSA (trama 1) y los 40 AESGCM (tramas 2–41).
- PIN `4827`, derivación AES y 40 mensajes descifrados y autenticados.
- Siete pruebas automatizadas aprobadas, incluidas alteraciones de ciphertext, nonce y tag.
- Informe con explicación de algoritmos, Scrypt, autenticación, PQC y las 40 transacciones.

Te queda revisar visualmente los paquetes en Wireshark, tomar pantallazos y completar tus datos en el informe. El PDF original es una plantilla/enunciado; no contenía un desarrollo personal previo.

## 2. Aplicaciones

| Aplicación | Para qué la usarás |
| --- | --- |
| Docker Desktop | Mantener funcionando el contenedor y mostrar su estado |
| Terminal de macOS | Ejecutar comandos y mostrar sus resultados |
| Wireshark | Abrir los PCAP, inspeccionar campos y tomar evidencias |
| Word o LibreOffice Writer | Editar `informe/Informe_Laboratorio_4.docx` y exportar la entrega a PDF |
| Excel/Numbers, opcional | Revisar `resultados/transacciones.csv` |

Docker y Wireshark ya están instalados en este Mac. El trabajo se hizo en `/Users/cris/lab-4-cripto`. No necesitas Kali ni una máquina virtual adicional.

## 3. Evidencias de Docker y SSH

Abre Docker Desktop y luego Terminal:

```sh
cd /Users/cris/lab-4-cripto
docker compose ps
docker compose exec ssh /usr/sbin/sshd -T | grep -E '^(kexalgorithms|ciphers|macs|hostkeyalgorithms) '
```

**Pantallazo E1:** contenedor `Up`/`healthy`, puerto `127.0.0.1:2222`, y el Dockerfile abierto en tu editor. La construcción ya está documentada en `evidencias/ssh-20261104-164221/01-build.log`.

**Pantallazo E2:** las cuatro líneas de configuración efectiva. Mostrar el archivo de configuración solo no demuestra que el servidor lo esté usando; la salida de `sshd -T` sí permite comprobarlo.

Para mostrar una conexión funcional interactiva:

```sh
ssh -F /dev/null -p 2222 -i .local/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=.local/known_hosts -o KexAlgorithms=curve25519-sha256 -o Ciphers=aes256-ctr -o MACs=hmac-sha2-256 -o HostKeyAlgorithms=ssh-ed25519 alumno@127.0.0.1
```

Dentro ejecuta `whoami`, `hostname` y `echo LAB4_SSH_OK`. **Pantallazo E3:** comando SSH y resultados. Sal con `exit`. La autenticación usa una clave Ed25519 local, por eso no pide contraseña.

## 4. Analizar el SSH en Wireshark

Abre **Wireshark → File → Open** y selecciona:

`evidencias/ssh-20261104-164221/06-ssh.pcap`

La captura automática se tomó con tcpdump dentro del contenedor y se verificó con TShark. Wireshark puede abrirla directamente. No se ha tomado todavía un pantallazo de su interfaz gráfica.

En la barra superior de filtro de visualización escribe `tcp.port == 22` y presiona Enter. Verás 42 paquetes. Para ir a un número, usa **Go → Go to Packet**, o un filtro como `frame.number == 8`.

| Qué observar | Tramas de esta captura | Qué explicar en el informe |
| --- | --- | --- |
| IP, puertos y establecimiento TCP | 1, 2, 3 | Cliente `172.22.0.1:55228` → servidor `172.22.0.2:22`, SYN/SYN-ACK/ACK. Se ven direcciones internas por capturar dentro de Docker. |
| Versiones del protocolo y software | 4 y 6 | Banners `SSH-2.0-OpenSSH_10.2` y `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`, visibles antes del cifrado. |
| Algoritmos ofrecidos | 8 y 10 | Expande `SSH Protocol → SSH Version 2 → Key Exchange Init → Algorithms`. Identifica intercambio, host key, cifrado y MAC en ambos sentidos. |
| Clave pública y firma del servidor | 13 | Expande `Key Exchange Reply`: host key y firma `ssh-ed25519`; la clave privada no viaja. |
| Activación del cifrado y datos posteriores | 13, 14 y 15 en adelante | `New Keys` inicia el uso de claves. Después aparecen `Encrypted packet`; no se leen comandos ni respuestas. Siguen visibles tamaño, dirección y tiempo. |

**Pantallazo E4:** tramas 1–10, con IP/puertos y banners. **E5:** trama 8 expandida mostrando los cuatro algoritmos. **E6:** trama 13 o 14 con `New Keys` y varios paquetes cifrados posteriores.

Los nombres `ext-info-s` y `kex-strict-s-v00@openssh.com` que aparecen junto al KEX son indicadores de extensiones de SSH, no un algoritmo alternativo negociado. El log del cliente confirma los cuatro algoritmos efectivos.

### Si debes capturar tú mismo desde la interfaz de Wireshark

El enunciado pide iniciar Wireshark antes de conectar. Para documentar literalmente ese procedimiento:

1. En Wireshark, selecciona **Loopback: lo0**, porque el cliente se conecta a `127.0.0.1`.
2. En opciones de captura, usa el filtro de captura `tcp port 2222` y comienza a capturar.
3. Ejecuta la conexión SSH del paso 3 y los tres comandos de prueba; termina con `exit`.
4. Detén la captura y guarda como `evidencias/ssh-wireshark-manual.pcapng`.
5. Usa el filtro de visualización `tcp.port == 2222`. Si aparece solo TCP, clic derecho en un paquete → **Decode As… → TCP port 2222 → SSH**.
6. Repite el análisis de la tabla; **los números de trama y las IP serán distintos**. En loopback aparecerá `127.0.0.1` en ambos extremos.

Si Wireshark no puede acceder a las interfaces, instala el componente **ChmodBPF** incluido con Wireshark para macOS y vuelve a abrirlo. No hace falta activar captura en Wi-Fi para esta conexión local.

## 5. Analizar la captura antigua

Abre `datos/transacciones_cifradas.pcap` en Wireshark. Es un archivo distinto de la captura SSH.

**RSA:** filtro `tcp contains "RSA_PIN|"`. Debe aparecer **la trama 1**, IP origen `10.10.10.10`, destino `10.10.10.20`, puertos `49152 → 4444`. Expande **Data** y mira el panel inferior de bytes. **Pantallazo E7:** filtro, trama y bytes del marcador y de la salt.

Los offsets siguientes se cuentan desde el inicio del **payload TCP**, no desde el inicio de toda la trama:

| Campo RSA | Rango de bytes, inclusivo | Longitud |
| --- | --- | --- |
| `RSA_PIN\|` | 0–7 | 8 bytes |
| Salt | 8–23 | 16 bytes |
| PIN cifrado RSA | 24–279 | 256 bytes |

Salt real: `1a065da01a70284041b93dd58e988907`. El RSA es de 2048 bits, por eso el ciphertext ocupa 256 bytes aunque el PIN tenga cuatro dígitos. En esta captura las cabeceras IP y TCP miden 20 bytes cada una; si seleccionas el paquete completo, suma 40 a esos offsets.

**AES:** filtro `tcp contains "AESGCM|"`. Deben aparecer **40 paquetes, tramas 2–41**. **Pantallazo E8:** filtro y contador de 40 paquetes visibles. **E9:** trama 2, Data y bytes del nonce.

| Campo AESGCM | Rango de bytes del payload | Longitud |
| --- | --- | --- |
| `AESGCM\|` | 0–6 | 7 bytes |
| Nonce | 7–18 | 12 bytes |
| Ciphertext | Desde 19 hasta antes del tag | Variable |
| Tag | Últimos 16 bytes | 16 bytes |

En la trama 2: payload de 119 bytes, nonce `2f0f7c0cec6fc6216066c11e`, ciphertext de 84 bytes (offsets 19–102) y tag `6f6812d39bd45875e789fe6b5f0e7753` (103–118). **No separes todo por `|`**: ese byte también aparece dentro de los datos binarios, incluso en este nonce.

Wireshark permite identificar las etiquetas y extraer bytes; el descifrado y la autenticación los realiza Python con las claves del laboratorio. El PIN y los nombres no se ven en claro dentro del PCAP.

## 6. Mostrar el descifrado y las pruebas

En Terminal:

```sh
cd /Users/cris/lab-4-cripto
.venv/bin/python scripts/descifrar.py
.venv/bin/python -m unittest discover -s tests -v
```

**Pantallazo E10:** PIN, salt, clave AES, parámetros Scrypt, contador de 40 transacciones y primeras transacciones con `VERIFICADA`. **E11:** las siete pruebas y `OK`. El resultado completo está en `resultados/transacciones.txt`; no hace falta fotografiar las 40 transacciones si adjuntas la tabla y el archivo completo.

Debes poder explicar este recorrido:

`PCAP → RSA_PIN| → salt + PIN cifrado → clave privada RSA/OAEP-SHA256 → PIN → Scrypt → clave AES → nonce + ciphertext + tag → AESGCM.decrypt → mensaje autenticado`

## 7. Informe y correspondencia con los 60 puntos

| Criterio | Puntos | Qué incluir |
| --- | --- | --- |
| Dockerfile y contenedor SSH | 5 | Dockerfile, E1 y registro de construcción |
| Configuración SSH | 5 | `sshd_config`, E2 y E5 |
| Explicación de algoritmos | 5 | Tabla del informe: intercambio, cifrado, integridad y firma |
| Conexión cliente-servidor | 5 | E3 y salida de sesión |
| Análisis de tráfico SSH | 5 | E4–E6 y al menos tres observaciones explicadas |
| Paquetes relevantes | 5 | E7–E9, trama 1 y tramas 2–41 |
| Extracción y PIN | 5 | Offsets, salt, RSA-OAEP y PIN 4827; E10 |
| Scrypt | 6 | 32 bytes, n=16384, r=8, p=1; función de salt y costos |
| AES-GCM y autenticidad | 6 | Nonce, tag, `decrypt`, rechazo de alteraciones; E10–E11 |
| Script y transacciones | 8 | `descifrar.py`, tabla de 40 mensajes y TXT/CSV |
| PQC | 5 | Respuesta técnica del informe: claves RSA no sirven para ML-KEM |

Abre el DOCX en Word/LibreOffice, completa tus datos, agrega E1–E11, revisa las conclusiones y exporta a PDF. Si usas Overleaf, puedes trasladar el contenido del Markdown a `informe/plantilla_original.tex`. El PDF generado es un borrador con resultados reales: conserva marcadores de las capturas visuales pendientes y no debe confundirse con una entrega ya revisada por ti.
