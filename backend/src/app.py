import joblib
import pandas as pd
from flask import Flask, jsonify, request, redirect, url_for, session
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.abspath(
    os.path.join(BASE_DIR, '../../ml-service/spam_gmail.pkl')
)
model_detect_email = joblib.load(MODEL_PATH)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, 'credentials.json')

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly'
]

REDIRECT_URI = 'http://127.0.0.1:8000/oauth2callback'


@app.route('/')
def index():
    return '<a href="/login">Login with Google</a>'


@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    session['state'] = state
    session['code_verifier'] = flow.code_verifier

    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session['state'],
        redirect_uri=REDIRECT_URI
    )
    flow.code_verifier = session['code_verifier']

    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials

    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': list(creds.scopes)
    }

    return redirect(url_for('emails'))


@app.route('/emails')
def emails():
    creds_data = session.get('credentials')

    if not creds_data:
        return redirect(url_for('login'))

    creds = Credentials(**creds_data)

    service = build('gmail', 'v1', credentials=creds)

    results = service.users().messages().list(
        userId='me',
        maxResults=10
    ).execute()

    messages = results.get('messages', [])

    output = '<h1>Recent Emails</h1>'
    for msg in messages:
        output += f'<p>{msg["id"]}</p>'

    return output


@app.route("/detect_email", methods=["POST"])
def detect_email():
    try:
        data = request.json
        input_convert = pd.DataFrame(data)
        predictions = model_detect_email.predict(input_convert)
        return jsonify({"status": "Success",
                        "predictions": [int(p) for p in predictions]})
    except Exception as e:
        return jsonify({"status": "Error",
                        "message": str(e)}), 400


if __name__ == "__main__":
    app.run(port=8000, debug=True)
