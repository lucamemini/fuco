#!/bin/bash

source venv/bin/activate
export FLASK_APP="fuco.py"
flask run --host=0.0.0.0 --port=5000

