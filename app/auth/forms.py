from flask_wtf import FlaskForm
from flask_babel import lazy_gettext as _l
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from app.models import User

class LoginForm(FlaskForm):
    username = StringField(_l('Username'), validators = [DataRequired()])
    password = StringField(_l('Password'), validators = [DataRequired()])
    remember_me = BooleanField(_l('Remember me'))
    submit = SubmitField(_l('Log in'))

class RegistrationForm(FlaskForm):
    username = StringField(_l('Username'), validators = [DataRequired()])
    email = StringField(_l('Email'), validators = [DataRequired(), Email()])
    password = StringField(_l('Password'), validators = [DataRequired()])
    password2 = StringField(_l('Repeat Password'),
                            validators = [DataRequired(), EqualTo('password')])
    remember_me = BooleanField(_l('Remember me'))
    submit = SubmitField(_l('Register'))

    def validate_username(self, username):
        user = User.query.filter_by(username = username.data).first()
        if user is not None:
            raise ValidationError(_l('Please enter a different username'))

    def validate_email(self, email):
        user = User.query.filter_by(email = email.data).first()
        if user is not None:
            raise ValidationError(_l('Please enter a different email'))

class ResetPasswordRequestForm(FlaskForm):
    email = StringField(_l('Email'), validators = [DataRequired(), Email()])
    submit = SubmitField(_l('Request Password Reset'))

class ResetPasswordForm(FlaskForm):
    password = StringField(_l('Password'), validators = [DataRequired()])
    password2 = StringField(_l('Repeat Password'),
                            validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField(_l('Reset Password'))
