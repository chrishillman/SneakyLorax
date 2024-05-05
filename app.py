from datetime import timedelta

import wtforms
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, jsonify, send_file
from flask_security import ResetPasswordForm
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField as BooleanFormField, SubmitField, SelectField, \
                     SelectMultipleField, TextAreaField, validators
from playhouse.flask_utils import FlaskDB
from peewee import *
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, \
    login_remembered, login_fresh, user_loaded_from_cookie, user_needs_refresh
import hashlib
import pypugjs
from wtforms.fields.simple import HiddenField

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
# Generate a nice key using secrets.token_urlsafe()
app.config['SECRET_KEY'] = "sdlkfjowrmnjwhrerjsdmkflskjeoighlkjsdflksdj"
# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
# Generate a good salt using: secrets.SystemRandom().getrandbits(128)
password_salt = "ovpoeinakjsdhflkjnweiublrkjfnksjrfnfksdjhfwe"
app.config['SECURITY_PASSWORD_SALT'] = password_salt
app.config['DATABASE'] = {
    'name': 'database.db',
    'engine': 'peewee.SqliteDatabase',
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=6)
app.jinja_env.add_extension('pypugjs.ext.jinja.PyPugJSExtension')

# Create database connection object
db = FlaskDB(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Database Models
class Role(db.Model):
    name = CharField(unique=True)
    description = TextField(null=True)
    permissions = TextField(null=True)

class User(db.Model):
    username = TextField()
    password = TextField() # Hashed value of password
    preferences = TextField(default="") # JSON of colors, etc
    permissions = TextField(default="") # JSON of object permissions
    active = BooleanField(default=True)
    authenticated = BooleanField(default=False)
    roleid = ForeignKeyField(Role)

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return self.active


# Helper Functions
def hashme(cleartext):
    return hashlib.md5((cleartext + password_salt).encode()).hexdigest()

# App Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Log In')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[validators.DataRequired()])
    verifypassword = PasswordField('Verify Password', \
                    validators=[validators.DataRequired(), \
                    validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

class UserForm(FlaskForm):
    id = HiddenField()
    username = StringField('Username', validators=[validators.DataRequired()])
    active = BooleanFormField('Active', default=True)
    password = PasswordField('Password')
    roleid = SelectField('Role', coerce=int, choices=[(0, 'select a role')], validators=[validators.DataRequired()])
    submit = SubmitField('Save Changes')

class RoleForm(FlaskForm):
    id = HiddenField()
    name = StringField('Name', validators=[validators.DataRequired()])
    description = StringField('Description', validators=[validators.DataRequired()])
    permissions = TextAreaField('Permissions', validators=[validators.DataRequired()])
    submit = SubmitField('Save Changes')
# App routes
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))

# Views
@app.route('/')
@app.route('/index.html')
@login_required
def index():
    return render_template('index.pug')

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    loginform = LoginForm()
    if request.method == 'POST':
        if loginform.validate_on_submit():
            username = loginform.username.data
            password = hashme(loginform.password.data)
            user = User.get_or_none((User.username == username) & (User.password == password))
            if user is not None:
                print("Logged in successfully")
                user.authenticated = True
                user.save()
                login_user(user, remember=True, duration=timedelta(hours=6))
                return redirect(url_for('index'))
            else:
                print("Login failed")
        else:
            print("Invalid username or password")
    return render_template("login.pug", loginform=loginform)

@app.route('/logout.html')
@login_required
def logout():
    current_user.authenticated = False
    current_user.save()
    logout_user()
    return redirect(url_for('login'))

@app.route('/resetpassword.html', methods=['GET', 'POST'])
@login_required
def resetpassword():
    passwordresetform = ResetPasswordForm()
    message = False
    if request.method == "POST":
        newpassword = hashme(passwordresetform.password.data)
        current_user.password = newpassword
        current_user.save()
        message = "Password changed successfully"
    return render_template("resetpassword.pug", passwordresetform=passwordresetform, message=message)

@app.route('/user-get.html')
@login_required
def users_get():
    allusers = User.select().join(Role)
    return render_template("user-get.pug", allusers=allusers)

@app.route('/user-add.html', methods=['GET', 'POST'])
@app.route('/user-edit.html', methods=['GET', 'POST'])
@login_required
def user_add():
    userform = UserForm()
    message = False
    url = url_for('user_add')
    allroles = Role.select()
    for role in allroles:
        userform.roleid.choices.append((role.id, role.name))
    edituser = request.values.get('userid', None)
    if request.method == "POST":
        if userform.validate_on_submit():
            username = userform.username.data
            roleid = userform.roleid.data
            password = ''
            if userform.password.data:
                password = hashme(userform.password.data)
            active = userform.active.data
            if edituser:
                thisuser = User.get_or_none(User.id == edituser)
                if thisuser:
                    thisuser.username = username
                    thisuser.roleid = roleid
                    if password:
                        thisuser.password = password
                    thisuser.active = active
                    thisuser.save()
                    message = "User updated successfully"
            else:
                User.create(username=username, roleid=roleid, password=password, active=active)
                message = "User added successfully"
    if request.method == "GET" and edituser:
        thisuser = User.get_or_none(User.id == edituser)
        if thisuser:
            url = url_for('user_add') + f"?userid={thisuser.id}"
            userform.id.data = thisuser.id
            userform.username.data = thisuser.username
            userform.active.data = thisuser.active
            userform.roleid.data = thisuser.roleid.id
    return render_template("user-add.pug", userform=userform, message=message, url=url)

@app.route('/role-get.html')
@login_required
def role_get():
    allroles = Role.select()
    return render_template("role-get.pug", allroles=allroles)

@app.route('/role-add.html', methods=['GET', 'POST'])
@app.route('/role-edit.html', methods=['GET', 'POST'])
@login_required
def role_add():
    roleform = RoleForm()
    message = False
    url = url_for('role_add')
    editrole = request.values.get('roleid', None)
    if request.method == "POST":
        if roleform.validate_on_submit():
            rolename = roleform.name.data
            roledescription = roleform.description.data
            rolepermissions = roleform.permissions.data
            if editrole:
                thisrole = Role.get_or_none(Role.id == editrole)
                if thisrole:
                    thisrole.name = rolename
                    thisrole.description = roledescription
                    thisrole.permissions = rolepermissions
                    thisrole.save()
                    message = "Role updated successfully"
            else:
                Role.create(name=rolename, description=roledescription, permissions=rolepermissions)
                message = "Role added successfully"
    if request.method == "GET" and editrole:
        thisrole = Role.get_or_none(Role.id == editrole)
        if thisrole:
            url = url_for('role_add') + f"?roleid={thisrole.id}"
            roleform.id.data = thisrole.id
            roleform.name.data = thisrole.name
            roleform.description.data = thisrole.description
            roleform.permissions.data = thisrole.permissions
    return render_template("role-add.pug", roleform=roleform, message=message, url=url)

# one time setup
with app.app_context():
    db.database.create_tables([Role, User])
    if Role.get_or_none(name="administrator") is None:
        Role.create(name="administrator", description="Administrator", permissions="{User:'CRUD'}")
    if User.get_or_none(username="admin") is None:
        User.create(username="admin", password=hashme("ABCdef123$%^"), roleid=1, active=True)


if __name__ == '__main__':
    app.run()
