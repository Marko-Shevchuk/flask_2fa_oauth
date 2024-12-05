from flask import render_template, url_for, flash, redirect, request, session, abort
from flask_login import login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlencode
import random
import string
import pyotp, qrcode
from io import BytesIO
import base64

from app import app, serializer, generate_confirmation_token, generate_password_hash, mail
from app.extensions import db, admin_required
from app.models import User, LoginAttempt

from flask_mail import Message
import requests
import os
import secrets



captcha_value = ''.join(random.choices(string.ascii_letters + string.digits, k=6))



@app.route("/")
@login_required
def index():
    return render_template("mainpage.html", user=current_user)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


from datetime import datetime, timedelta

MAX_ATTEMPTS = 4
LOCKOUT_DURATION = timedelta(minutes=1)


@app.route('/login', methods=['GET', 'POST'])
def login():
    from app.forms import LoginForm
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        login_attempt = LoginAttempt(email=form.email.data)

        if user:
            if user.locked_until and user.locked_until > datetime.utcnow():
                flash('ACCOUNT BLOCKED. TRY AGAIN LATER.')
                return redirect(url_for('login'))

            if check_password_hash(user.password, form.password.data):

                if user.is_two_factor_enabled:
                    session['2fa_user_id'] = user.id
                    return redirect(url_for('two_factor_auth'))

                login_attempt.success = True
                login_user(user)

                user.failed_attempts = 0
                user.locked_until = None
                db.session.add(login_attempt)
                db.session.commit()

                flash('Successful login')
                return redirect(url_for('index'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_ATTEMPTS:
                    user.locked_until = datetime.now() + LOCKOUT_DURATION
                    flash(f'Your account was blocked for {LOCKOUT_DURATION.total_seconds()} seconds.')
                else:
                    flash('Incorrect email or password.')
        else:
            flash(f'User {form.email.data} does not exist. Register an account.')
            return redirect(url_for('register'))

        db.session.add(login_attempt)
        db.session.commit()

    return render_template('login.html', form=form)


@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    from app.forms import TwoFactorForm
    form = TwoFactorForm()

    user_id = session.get('2fa_user_id')
    if not user_id:
        flash("Error")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    login_attempt = LoginAttempt(email=user.email)

    if form.validate_on_submit():
        totp = pyotp.TOTP(user.secret_token)

        if totp.verify(form.code.data):
            login_user(user)
            session.pop('2fa_user_id', None)

            login_attempt.success = True
            db.session.add(login_attempt)
            db.session.commit()

            flash('Successful 2FA')
            return redirect(url_for('index'))
        else:
            login_attempt.success = False
            db.session.add(login_attempt)
            db.session.commit()
            flash('Wrong 2FA code.')

    return render_template('two_factor_auth', form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    from app.forms import RegistrationForm
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Successful registration. Proceed to login.')
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@login_required
@app.route('/send_confirmation/<email>')
def send_confirmation(email):
    if not current_user.confirmed:
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = f'Click to activate account: <a href="{confirm_url}">ACTIVATE YOUR ACCOUNT</a>'
        msg = Message('Account activation', recipients=[email], html=html)
        mail.send(msg)
        return render_template("confirmation.html")
    else:
        flash("Account already activated.")
        return redirect(url_for('index'))


@app.route('/confirm/<token>')
def confirm_email(token):
    if current_user.confirmed:
        flash("Account already activated.")
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=3600)  # 1 hour
    except:
        flash('Error on account activation.')

    current_user.confirmed = True
    db.session.commit()

    flash('Account activated!')
    return redirect(url_for('index'))


@app.route('/admin/login_attempts')
@login_required
@admin_required
def login_attempts():
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('login_attempts.html', attempts=attempts)


@app.route('/enable_2fa', methods=['POST', 'GET'])
@login_required
def enable_2fa():
    if current_user.is_two_factor_enabled:
        flash("2FA already enabled.")
        return redirect(url_for("index"))

    current_user.secret_token = pyotp.random_base32()
    current_user.is_two_factor_enabled = True
    db.session.commit()

    totp = pyotp.TOTP(current_user.secret_token)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="flaskapplication")

    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, "PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return render_template('enable_2fa.html', qr_code_base64=qr_code_base64)


@app.route('/disable_2fa', methods=['POST', 'GET'])
@login_required
def disable_2fa():
    current_user.is_two_factor_enabled = False
    current_user.secret_token = None
    db.session.commit()
    flash("2FA disabled.")
    return redirect(url_for('index'))


from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(app.secret_key)


def generate_confirmation_token(email):
    return serializer.dumps(email, salt=os.getenv('PASSWORD_RESET_SALT'))


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    from app.forms import PasswordResetRequestForm
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_confirmation_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            html = f'Click to reset password: <a href="{reset_url}">Reset password</a>'
            msg = Message('Reset password', recipients=[user.email], html=html)
            mail.send(msg)
            flash('Link to reset password sent to your email.')
            return redirect(url_for("login"))
        else:
            flash('Account with this email doesnt exist...')
    return render_template('reset_password_request.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except:
        flash('Bad link or token is no longer valid.')
        return redirect(url_for('reset_password_request'))

    from app.forms import PasswordResetForm
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        user.password = generate_password_hash(form.password.data)
        user.locked_until = None
        user.failed_attempts = 0
        db.session.commit()
        flash('Your password was updated..')
        return redirect(url_for('login'))
    return render_template('reset_password.html.html', form=form)


@app.route('/authorize/<provider>')
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    session['oauth2_state'] = secrets.token_urlsafe(16)

    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })

    return redirect(provider_data['authorize_url'] + '?' + qs)


@app.route('/callback/<provider>')
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    if 'error' in request.args:
        for k, v in request.args.items():
            if k.startswith('error'):
                flash(f'{k}: {v}')
        login_attempt = LoginAttempt(email=session.get('oauth_email'))
        login_attempt.success = False
        db.session.add(login_attempt)
        db.session.commit()
        return redirect(url_for('index'))

    if request.args['state'] != session.get('oauth2_state'):
        abort(401)

    if 'code' not in request.args:
        abort(401)

    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('oauth2_callback', provider=provider, _external=True),
    }, headers={'Accept': 'application/json'})
    if response.status_code != 200:
        abort(401)

    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)

    response = requests.get(provider_data['userinfo']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,
        'Accept': 'application/json',
    })
    if response.status_code != 200:
        abort(401)
    email = provider_data['userinfo']['email'](response.json())

    login_attempt = LoginAttempt(email=email)
    if response.status_code == 200:
        user = db.session.scalar(db.select(User).where(User.email == email))
        if user is None:
            user = User(
                email=email,
                password=secrets.token_hex(16),
                confirmed=True,
                failed_attempts=0,
                locked_until=None,
                is_admin=False,
                is_two_factor_enabled=False,
                secret_token=None
            )
            db.session.add(user)
            db.session.commit()

        if user.is_two_factor_enabled:
            session['2fa_user_id'] = user.id
            login_attempt.success = False
        else:
            user.locked_until = None
            user.failed_attempts = 0
            login_user(user)
            login_attempt.success = True
    else:
        login_attempt.success = False

    db.session.add(login_attempt)
    db.session.commit()

    if login_attempt.success:
        return redirect(url_for('index'))
    else:
        flash('Google auth error.')
        return redirect(url_for('login'))
