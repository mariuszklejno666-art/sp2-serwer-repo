from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField("Login", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Hasło", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Zaloguj")
