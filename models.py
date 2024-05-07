from peewee import *
from playhouse.flask_utils import *

db = FlaskDB()

class TestModel(db.Model):
    testname = CharField()
    testdesc = TextField()
    readflag = BooleanField()

# Database Models


class Role(db.Model):
    name = CharField(unique=True)
    description = TextField(null=True)
    permissions = TextField(null=True)


class User(db.Model):
    username = TextField()
    password = TextField()  # Hashed value of password
    preferences = TextField(default="")  # JSON of colors, etc
    permissions = TextField(default="")  # JSON of object permissions
    active = BooleanField(default=True)
    authenticated = BooleanField(default=False)
    roleid = ForeignKeyField(Role)

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return self.active


