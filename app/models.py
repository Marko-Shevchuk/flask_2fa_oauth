from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from app.extensions import db,login_manager
from flask_login import UserMixin

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))
class User(db.Model, UserMixin):
    id = db.Column(db.String(80), primary_key=True)
    username = db.Column(db.String(80), unique=True, index=True)
    hashed_password = db.Column(db.String(128))
    email = db.Column(db.String(120), index=True)

