from flask import Flask
from app.extensions import db,login_manager
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = "verysecret"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"


db.init_app(app=app)
login_manager.init_app(app=app)
login_manager.login_view = "login"
login_manager.login_message = "Please authorize."

migrate = Migrate()
migrate.init_app(app, db)

from app import views