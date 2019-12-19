# -*- coding: utf-8 -*-
from src import db
from datetime import datetime

# user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(10), unique=True)
    username = db.Column(db.String(10), unique=True)
    email = db.Column(db.String(100), unique=True)
    pasword = db.Column(db.String(10), unique=True)
    is_curator = db.Column(db.Boolean)
    is_validator = db.Column(db.Boolean)
    is_admin = db.Column(db.Boolean)
    upgrade_rquests =  db.relationship('UpgradeRequest', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.public_id}', '{self.username}', '{self.email}')"


# upgrade request

class UpgradeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(10), unique=True)
    request_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    request_type = db.Column(db.String(20), unique=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_accepted = db.Column(db.Boolean)
    is_denied = db.Column(db.Boolean)
    under_processing = db.Column(db.Boolean)

    def __repr__(self):
        return f"UpgradeRequest('{self.request_id}', {self.request_timestamp}, '{self.request_type}')"




