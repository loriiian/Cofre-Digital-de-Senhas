from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.models import User

SECURITY_QUESTIONS = [
    ('pet', 'Qual era o nome do seu primeiro animal de estimação?'),
    ('city', 'Em que cidade os seus pais se conheceram?'),
    ('teacher', 'Qual era o nome do seu professor preferido do ensino médio?'),
    ('street', 'Qual é o nome da rua onde cresceu?'),
    ('food', 'Qual era a sua comida preferida na infância?')
]

class RegistrationForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    security_question = SelectField('Pergunta de Segurança', choices=SECURITY_QUESTIONS, validators=[DataRequired()])
    security_answer = StringField('Resposta de Segurança', validators=[DataRequired()])
    submit = SubmitField('Registrar')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nome de usuário já existe.')

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')

class PasswordForm(FlaskForm):
    service_name = StringField('Nome do Serviço', validators=[DataRequired()])
    username_or_email = StringField('Usuário ou E-mail', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Salvar Senha')

class RequestResetForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    submit = SubmitField('Avançar')

class VerifyAnswerForm(FlaskForm):
    answer = StringField('Resposta de Segurança', validators=[DataRequired()])
    submit = SubmitField('Verificar Resposta')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Redefinir Senha')

class ImportForm(FlaskForm):
    file = FileField('Ficheiro de Backup (.enc)', validators=[
        FileRequired(),
        FileAllowed(['enc'], 'Apenas ficheiros .enc são permitidos!')
    ])
    submit = SubmitField('Importar')