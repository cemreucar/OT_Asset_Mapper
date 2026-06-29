@echo off
echo Installing build dependency...
python -m pip install pyinstaller

echo Building OT Asset Mapper Desktop EXE...
pyinstaller --onefile --windowed --name OT_Asset_Mapper app_desktop.py

echo.
echo Build completed.
echo Your EXE should be here:
echo dist\OT_Asset_Mapper.exe
pause
