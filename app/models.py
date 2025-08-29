from app import db, login_manager, bcrypt
from flask_login import UserMixin
from cryptography.fernet import Fernet


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)
    security_question = db.Column(db.String(150), nullable=True)
    security_answer_hash = db.Column(db.String(60), nullable=True)
    passwords = db.relationship('PasswordEntry', backref='owner', lazy=True)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        self.encryption_key = Fernet.generate_key()

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_security_answer(self, answer):
        self.security_answer_hash = bcrypt.generate_password_hash(answer).decode('utf-8')

    def check_security_answer(self, answer):
        if not self.security_answer_hash:
            return False
        return bcrypt.check_password_hash(self.security_answer_hash, answer)


class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100), nullable=False)
    username_or_email = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def encrypt_password(self, password, key):
        f = Fernet(key)
        self.encrypted_password = f.encrypt(password.encode())

    def decrypt_password(self, key):
        f = Fernet(key)
        return f.decrypt(self.encrypted_password).decode()