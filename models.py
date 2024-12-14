from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    surname = db.Column(db.Text, nullable=False)
    login = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(20), nullable=False)
    registeredAt = db.Column(db.DATE, nullable=False)
    isAdmin = db.Column(db.Boolean, default=False)
