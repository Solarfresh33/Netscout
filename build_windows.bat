@echo off
REM ===========================================================================
REM  CAMILLE - Build script for Windows
REM  Produces a single-file desktop executable: dist\CAMILLE.exe
REM ===========================================================================

echo.
echo  ========================================
echo   CAMILLE - Construction du .exe Windows
echo  ========================================
echo.

REM --- Check Python is available ---------------------------------------------
where python >nul 2>nul
if errorlevel 1 (
    echo  [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo  Telecharge-le sur https://www.python.org/downloads/
    pause
    exit /b 1
)

REM --- Create / use a clean virtual environment ------------------------------
echo  [1/4] Creation de l'environnement virtuel...
python -m venv .build-venv
call .build-venv\Scripts\activate.bat

REM --- Install dependencies + build tools ------------------------------------
echo  [2/4] Installation des dependances...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
pip install pyinstaller pywebview --quiet

REM --- Build -----------------------------------------------------------------
echo  [3/4] Compilation (cela peut prendre 1-2 minutes)...
pyinstaller CAMILLE.spec --noconfirm --clean

REM --- Done ------------------------------------------------------------------
echo  [4/4] Termine.
echo.
if exist dist\CAMILLE.exe (
    echo  ========================================
    echo   SUCCES : dist\CAMILLE.exe
    echo  ========================================
    echo  Double-clique sur dist\CAMILLE.exe pour lancer l'application.
) else (
    echo  [ERREUR] La compilation a echoue. Verifie les messages ci-dessus.
)
echo.
pause
