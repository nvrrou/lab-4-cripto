# Laboratorio 4 de Criptografía

## Script de descifrado

El script está en **[scripts/descifrar.py](scripts/descifrar.py)**.
Recupera el PIN con RSA-OAEP, deriva la clave AES con Scrypt y descifra las transacciones con AES-GCM, verificando su autenticidad.

## Transacciones en TXT

Las **40 transacciones recuperadas** están en **[resultados/transacciones.txt](resultados/transacciones.txt)**.
El archivo conserva los mensajes originales con ID, remitente, destinatario y monto, además del número de trama y el estado de autenticidad.

## Ejecutar el script

Desde la carpeta del proyecto, con las dependencias instaladas en `.venv`:

```sh
.venv/bin/python scripts/descifrar.py
```

Utiliza `datos/transacciones_cifradas.pcap`, `datos/clave_privada.pem` y `datos/clave_publica.pem`. Al finalizar correctamente, actualiza `resultados/transacciones.txt`.

