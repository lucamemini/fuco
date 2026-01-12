@echo off
venv\Scripts\activate
set FLASK_APP=fuco.py
flask run --host=0.0.0.0 --port=5000