from flask_wtf import FlaskForm
from wtforms import PasswordField,StringField,SubmitField
from wtforms.validators import DataRequired,Email,Length,ValidationError,EqualTo
import re

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired("Can't be empty"), Email("Incorrect email")])
    password = PasswordField('Password', validators=[DataRequired("Can't be empty")])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired("Can't be empty"), Email("Incorrect email")])
    password = PasswordField('Password', validators=[
        DataRequired("Can't be empty"),
        Length(min=8, message='Password 8 or more symbols required.')
    ])
    repeat_pass = PasswordField(validators=[DataRequired("Can't be empty"), EqualTo("password", message="Passwords don't match.")], label="Repeat password")
    submit = SubmitField('Register account')

    def validate_password(self, password):
        password_data = password.data

        if not re.search(r'[A-Z]', password_data):
            raise ValidationError("Password at least one capital letter required.")
        if not re.search(r'[a-z]', password_data):
            raise ValidationError("Password at least one lowercase letter required.")
        if not re.search(r'[0-9]', password_data):
            raise ValidationError("Password at least one digit required.")
        if not re.search(r'[!@#$%^&*(),.?]', password_data):
            raise ValidationError("Password at least one special character required.")

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email address is already registered.')