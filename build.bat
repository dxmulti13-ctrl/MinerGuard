@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo          MinerGuard - Build EXE
echo ========================================
py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements.txt
if errorlevel 1 goto error
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name MinerGuard --collect-all psutil src\minerguard.py
if errorlevel 1 goto error
echo.
echo EXE creado en dist\MinerGuard.exe
pause
exit /b 0
:error
echo Error al compilar. Revisa que Python 3.10+ este instalado y agregado al PATH.
pause
exit /b 1
