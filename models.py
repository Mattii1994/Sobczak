from app import db, app

from flask_login import UserMixin
from flask_security import Security, SQLAlchemyUserDatastore, RoleMixin
import datetime


class RolesUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
    role_id = db.Column('role_id', db.Integer, db.ForeignKey('role.id'))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    first_name = db.Column(db.String(25))
    surname = db.Column(db.String(30))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    active = db.Column(db.Boolean, default=True)
    logged_in = db.Column(db.Boolean)
    last_login = db.Column(db.DateTime, default=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users', lazy='dynamic'))


class Worker(db.Model):
    id_ = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer)
    id_room = db.Column(db.Integer)


class Rooms(db.Model):
    id_room = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.Integer, unique=True)
    floor = db.Column(db.Integer)
    description = db.Column(db.String(255))


class Sensor(db.Model):
    id_elem = db.Column(db.Integer, primary_key=True)
    sensor_brand = db.Column(db.String(35))
    sensor_name = db.Column(db.String(100))
    serial_number = db.Column(db.String(50))
    id_room = db.Column(db.Integer)
    mount_date = db.Column(db.DateTime, default=datetime.datetime.now().strftime("%Y-%m-%d"))
    ip_address = db.Column(db.String(17))
    last_signal = db.Column(db.DateTime)
    alive = db.Column(db.Boolean)
    signal = db.Column(db.Boolean)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_elem = db.Column(db.Integer)
    last_review = db.Column(db.Date)
    next_review = db.Column(db.Date)


class RevHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_elem = db.Column(db.Integer)
    rev_date = db.Column(db.DateTime)
    subcontractor = db.Column(db.String(50))
    description = db.Column(db.String(255))


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_elem = db.Column(db.Integer)
    date = db.Column(db.DateTime, default=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    author = db.Column(db.String(50))
    type_of_notification = db.Column(db.String(50))
    description = db.Column(db.String(255))
    read = db.Column(db.Boolean, default=False)
    ignored = db.Column(db.Boolean, default=False)
    public = db.Column(db.Boolean)


class TypeofNotification(db.Model):
    id_type = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)