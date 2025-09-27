@echo off
REM build_exe.bat — Build incident_logger.exe on Windows
REM Run this in the folder containing app.py and app_server.py

REM 1) Create & activate venv
py -m venv venv
call venv\Scripts\activate

REM 2) Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install pyinstaller waitress Flask Flask-WTF WTForms SQLAlchemy passlib xhtml2pdf

REM 3) Build EXE (one-folder build is more reliable with xhtml2pdf/reportlab)
pyinstaller --name incident_logger --noconsole --onedir app_server.py

echo.
echo Build complete: dist\incident_logger\incident_logger.exe
echo To run: cd dist\incident_logger && incident_logger.exe
