from flask import render_template, request, redirect, url_for, flash, session
import hashlib
from app.forms import LoginForm, RegistrationForm
from app.models import User
from app.extensions import db,login_manager
from app import app


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/', methods=['GET'])
def hello_world():
    return 'Hello World!'


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = hash_password(form.password.data)

        new_user = User(
            email=form.email.data,
            hashed_password=hashed_password,
            username=form.email.data  # Assuming usernames are based on emails
        )
        db.session.add(new_user)
        db.session.commit()

        session['logged_in'] = True
        session['username'] = new_user.email
        flash("Registration successful!", category='success')
        return redirect(url_for('profile'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            session['logged_in'] = True
            session['username'] = user.email
            flash("Login successful!", category='success')
            return redirect(url_for('profile'))
        else:
            flash("Invalid credentials.", category='error')

    return render_template('login.html', form=form)


@app.route('/profile')
def profile():
    if 'logged_in' in session:
        username = session['username']
        return render_template('profile.html', username=username)
    else:
        flash("Please log in first.", category='warning')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash("You have been logged out.", category='info')
    return redirect(url_for('login'))