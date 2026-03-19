@echo off
set FLASK_APP=fuco.py
venv\Scripts\python.exe -m flask run --host=0.0.0.0 --port=5000