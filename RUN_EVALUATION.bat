@echo off
setlocal
cd /d "%~dp0"
echo.
echo ============================================================
echo NETRA-MAIL AUTOMATED EVALUATION
echo ============================================================
echo.
python evaluate_netra.py
if errorlevel 2 (
    echo.
    echo Evaluation could not start. Is FastAPI running?
    echo Start it with:
    echo python -m uvicorn backend.main:app --reload --port 8000
)
echo.
pause
