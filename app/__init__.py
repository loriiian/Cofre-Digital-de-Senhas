from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from config import Config, basedir, os

custom_template_path = os.path.join(basedir, 'templates')
custom_static_path = os.path.join(basedir, 'static')

app = Flask(__name__, template_folder=custom_template_path, static_folder=custom_static_path)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
bcrypt = Bcrypt(app)

from app import routes, models