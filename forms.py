from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, BooleanField as BooleanFormField, SubmitField, SelectField,
                     HiddenField, TextAreaField, validators)
from colors import getcolors
# App Forms


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Log In')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[validators.DataRequired()])
    verifypassword = PasswordField('Verify Password',
                                   validators=[validators.DataRequired(),
                                               validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')


class UserForm(FlaskForm):
    id = HiddenField()
    username = StringField('Username', validators=[validators.DataRequired()])
    active = BooleanFormField('Active', default=True)
    password = PasswordField('Password')
    roleid = SelectField('Role', coerce=int, choices=[(0, 'select a role')], validators=[validators.DataRequired()])
    submit = SubmitField('Save Changes')

class UserPreferencesForm(FlaskForm):
    fgcolor = SelectField('Text Foreground Color', choices=getcolors("fg"), coerce=str, validators=[validators.DataRequired()])
    bgcolor = SelectField('Text Background Color', choices=getcolors("bg"), coerce=str, validators=[validators.DataRequired()])
    menufgcolor = SelectField('Menu/Button Foreground Color', choices=getcolors("fg"), coerce=str, validators=[validators.DataRequired()])
    menubgcolor = SelectField('Menu/Button Background Color', choices=getcolors("bg"), coerce=str, validators=[validators.DataRequired()])
    submit = SubmitField('Save Changes')

class RoleForm(FlaskForm):
    id = HiddenField()
    name = StringField('Name', validators=[validators.DataRequired()])
    description = StringField('Description', validators=[validators.DataRequired()])
    permissions = TextAreaField('Permissions', validators=[validators.DataRequired()])
    submit = SubmitField('Save Changes')