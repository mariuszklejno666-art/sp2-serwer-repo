from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp

USERNAME_REGEXP = Regexp(
    r"^[A-Za-z0-9_.-]+$",
    message="Dozwolone znaki: litery, cyfry, kropka, myślnik i podkreślenie.",
)


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField(
        "Nowe hasło",
        validators=[DataRequired(), Length(min=12, max=256)],
    )
    confirm_password = PasswordField(
        "Powtórz nowe hasło",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Hasła muszą być identyczne."),
        ],
    )
    force_change = BooleanField("Wymuś zmianę hasła przy następnym logowaniu", default=True)
    submit = SubmitField("Resetuj hasło")


class AccountActionForm(FlaskForm):
    submit = SubmitField("Wykonaj")


class GroupMembershipForm(FlaskForm):
    group_dn = SelectField("Grupa", validators=[DataRequired()], choices=[])
    submit = SubmitField("Zapisz")


class MoveUserForm(FlaskForm):
    target_ou_dn = SelectField("Docelowa jednostka OU", validators=[DataRequired()], choices=[])
    submit = SubmitField("Przenieś użytkownika")


class CreateUserForm(FlaskForm):
    username = StringField(
        "Nazwa użytkownika (login)",
        validators=[DataRequired(), Length(min=2, max=64), USERNAME_REGEXP],
    )
    given_name = StringField("Imię", validators=[DataRequired(), Length(max=64)])
    surname = StringField("Nazwisko", validators=[DataRequired(), Length(max=64)])
    display_name = StringField("Nazwa wyświetlana", validators=[Optional(), Length(max=128)])
    mail = StringField("E-mail", validators=[Optional(), Email(), Length(max=128)])
    password = PasswordField(
        "Hasło początkowe",
        validators=[DataRequired(), Length(min=6, max=256)],
    )
    confirm_password = PasswordField(
        "Powtórz hasło",
        validators=[
            DataRequired(),
            EqualTo("password", message="Hasła muszą być identyczne."),
        ],
    )
    organizational_unit = SelectField(
        "Jednostka OU", validators=[DataRequired()], choices=[]
    )
    groups = SelectMultipleField("Grupy początkowe", validators=[Optional()], choices=[])
    submit = SubmitField("Utwórz użytkownika")


class RenameUserForm(FlaskForm):
    new_username = StringField(
        "Nowa nazwa użytkownika (login)",
        validators=[DataRequired(), Length(min=2, max=64), USERNAME_REGEXP],
    )
    submit = SubmitField("Zmień nazwę")


class DeleteUserForm(FlaskForm):
    confirm_username = StringField(
        "Wpisz login użytkownika, aby potwierdzić usunięcie",
        validators=[DataRequired()],
    )
    submit = SubmitField("Usuń użytkownika")


class BulkUserActionForm(FlaskForm):
    action = SelectField(
        "Operacja",
        validators=[DataRequired()],
        choices=[
            ("enable", "Włącz konta"),
            ("disable", "Wyłącz konta"),
            ("unlock", "Odblokuj konta"),
        ],
    )
    submit = SubmitField("Wykonaj dla zaznaczonych")
