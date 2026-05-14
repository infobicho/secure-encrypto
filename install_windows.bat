@echo off
chcp 65001 >nul
title secure-encrypto — Installateur

echo.
echo   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
echo   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
echo   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
echo   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
echo   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
echo   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
echo.
echo   secure-encrypto v2.0 — Installateur Windows
echo   ──────────────────────────────────────────────────
echo.

:: Vérifier Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERREUR] Python non trouvé. Téléchargez Python 3.9+ depuis python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PY_VER=%%i
echo   [OK] Python %PY_VER% trouvé.
echo.

:: Mettre à jour pip
echo   -^> Mise à jour de pip...
python -m pip install --upgrade pip -q

:: Installer les dépendances
echo   -^> Installation des dépendances...
python -m pip install -r requirements.txt -q

if %errorlevel% neq 0 (
    echo.
    echo   [ERREUR] L'installation a échoué.
    pause
    exit /b 1
)

echo.
echo   ──────────────────────────────────────────────────
echo   [OK] Installation terminée !
echo.
echo   Pour démarrer l'application :
echo      python main.py
echo.
pause
