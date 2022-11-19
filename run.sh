#!/bin/bash

source venv/bin/activate
export FLASK_APP="api.py"
flask run --host=0.0.0.0

