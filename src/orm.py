from src import db

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


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creation_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    lastmod_timestamp = db.Column(db.DateTime, nullable=True)
    complete_timestamp = db.Column(db.DateTime, nullable=True)
    is_complete = db.Column(db.Boolean)
    is_validated = db.Column(db.Boolean)




