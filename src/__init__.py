# -*- coding: utf-8 -*-
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# flask app init

app = Flask(__name__)

# database init

db = SQLAlchemy(app)

# bcrypt init

bcrypt = Bcrypt(app)

# login manager init

#login_manager = LoginManager(app)

# global config
from src import config


# blueprint routes
from src.main.routes import main
from src.users.routes import users

# register blueprint
app.register_blueprint(main)
app.register_blueprint(users)

