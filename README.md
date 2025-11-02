python3 -m venv .venv
source .venv/bin/activate
Back: FLASK_APP=app.api.main:app flask run --port 5000 --debug
Front: ng s