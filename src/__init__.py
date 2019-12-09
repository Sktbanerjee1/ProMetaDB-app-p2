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
from src.annoation_dashboard.routes import annotation_dashboard
from src.database_dashboard.routes import database_dashboard
from src.main.routes import main

# register blueprint
app.register_blueprint(annoation_dashboard)
app.register_blueprint(database_dashboard)
app.register_blueprint(main)

