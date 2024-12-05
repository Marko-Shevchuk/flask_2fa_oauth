from flask import Flask,render_template,url_for,flash,redirect
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_required,login_user,LoginManager,current_user,logout_user
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db,login_manager
from flask_migrate import Migrate
import os

import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.secret_key = 'very secret'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['RECAPTCHA_PUBLIC_KEY'] = 'key' #replace with key
app.config['RECAPTCHA_PRIVATE_KEY'] = 'key' #replace with key

app.config['OAUTH2_PROVIDERS'] = {
    'google': {
        'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
        'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
        'token_url': 'https://accounts.google.com/o/oauth2/token',
        'userinfo': {
            'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
            'email': lambda json: json['email'],
        },
        'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
    },

}


app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='markoliubomirshevchykwork@gmail.com',
    MAIL_PASSWORD='pass',     # app password
    MAIL_DEFAULT_SENDER='markoliubomirshevchykwork@gmail.com',
    SECRET_KEY='mail_secret_key'
)

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_confirmation_token(email):
    return serializer.dumps(email, salt='email-confirmation-salt')

def send_confirmation_email(user_email):
    token = generate_confirmation_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = f'<p>Please confirm your email by clicking <a href="{confirm_url}">here</a>.</p>'
    subject = "Please confirm your email"
    msg = Message(subject=subject, recipients=[user_email], html=html)
    mail.send(msg)


db.init_app(app=app)

login_manager.init_app(app=app)
login_manager.login_view = "login"
login_manager.login_message = "Please authorize."

migrate = Migrate()
migrate.init_app(app, db)
from app import views
