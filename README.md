# MinerGuard

Scanner de indicadores de minería no autorizada para Windows 10/11. Interfaz en español.

## Compilar en Windows
1. Instala Python 3.10 o superior desde python.org y marca **Add Python to PATH**.
2. Extrae esta carpeta.
3. Haz doble clic en `build.bat`.
4. El ejecutable aparecerá en `dist\MinerGuard.exe`.

También puedes compilar desde una terminal en esta carpeta:

```bat
py -3 -m pip install -r requirements.txt
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name MinerGuard --collect-all psutil src\minerguard.py
```

## Uso
- Ejecuta MinerGuard. Para revisar servicios y entradas protegidas, usa clic derecho → **Ejecutar como administrador**.
- Pulsa **Iniciar análisis completo**.
- Guarda el informe TXT o JSON para revisar resultados.

## Alcance y limitaciones
Comprueba procesos, consumo de CPU, conexiones a puertos frecuentemente usados por pools, claves Run del registro, servicios, tareas programadas, nombres de archivos conocidos en carpetas habituales y datos de GPU NVIDIA mediante `nvidia-smi`.

**No es un antivirus ni garantiza detectar todos los mineros.** Los puertos y el consumo alto son señales contextuales, no pruebas. Puede haber falsos positivos y mineros que no coincidan con firmas conocidas. No elimina ni deshabilita nada automáticamente. Para una segunda opinión, ejecuta Microsoft Defender (incluido análisis sin conexión si hay sospecha persistente).

El análisis de archivos está limitado a 12 000 archivos en las carpetas habituales para evitar exploraciones excesivamente largas. La comprobación de GPU NVIDIA requiere que `nvidia-smi` esté disponible.
