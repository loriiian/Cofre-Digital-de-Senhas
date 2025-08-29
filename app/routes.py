from flask import render_template, url_for, flash, redirect, request, session, Response
from app import app, db
from app.forms import RegistrationForm, LoginForm, PasswordForm, RequestResetForm, VerifyAnswerForm, ResetPasswordForm, \
    SECURITY_QUESTIONS, ImportForm
from app.models import User, PasswordEntry
from flask_login import login_user, current_user, logout_user, login_required
from cryptography.fernet import Fernet
import json
import io


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        user.security_question = form.security_question.data
        user.set_security_answer(form.security_answer.data)
        db.session.add(user)
        db.session.commit()
        flash('A sua conta foi criada! Faça login agora.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registro', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login bem-sucedido!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login falhou. Verifique seu nome de usuário e senha.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', title='Dashboard', passwords=passwords)


@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    form = PasswordForm()
    if form.validate_on_submit():
        new_password_entry = PasswordEntry(
            service_name=form.service_name.data,
            username_or_email=form.username_or_email.data,
            owner=current_user
        )
        new_password_entry.encrypt_password(form.password.data, current_user.encryption_key)

        db.session.add(new_password_entry)
        db.session.commit()
        flash('Senha adicionada com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_password.html', title='Adicionar Senha', form=form)


@app.route('/view_password/<int:password_id>', methods=['POST'])
@login_required
def view_password(password_id):
    entry = PasswordEntry.query.get_or_404(password_id)
    if entry.owner != current_user:
        return {'error': 'Acesso negado'}, 403

    decrypted_pass = entry.decrypt_password(current_user.encryption_key)

    return {'password': decrypted_pass}


@app.route('/update_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def update_password(password_id):
    password_entry = PasswordEntry.query.get_or_404(password_id)
    if password_entry.owner != current_user:
        return redirect(url_for('dashboard'))

    form = PasswordForm()
    if form.validate_on_submit():
        password_entry.service_name = form.service_name.data
        password_entry.username_or_email = form.username_or_email.data
        password_entry.encrypt_password(form.password.data, current_user.encryption_key)
        db.session.commit()
        flash('Sua senha foi atualizada!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.service_name.data = password_entry.service_name
        form.username_or_email.data = password_entry.username_or_email

    return render_template('update_password.html', title='Atualizar Senha', form=form)


@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    password_entry = PasswordEntry.query.get_or_404(password_id)
    if password_entry.owner != current_user:
        return redirect(url_for('dashboard'))

    db.session.delete(password_entry)
    db.session.commit()
    flash('Sua senha foi removida!', 'success')
    return redirect(url_for('dashboard'))


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.security_question:
            session['reset_username'] = user.username
            return redirect(url_for('verify_answer'))
        else:
            flash('Usuário não encontrado ou sem pergunta de segurança configurada.', 'danger')
    return render_template('reset_request.html', title='Redefinir Senha', form=form)


@app.route("/reset_password/verify", methods=['GET', 'POST'])
def verify_answer():
    if 'reset_username' not in session:
        return redirect(url_for('reset_request'))

    username = session['reset_username']
    user = User.query.filter_by(username=username).first()
    if not user:
        session.pop('reset_username', None)
        return redirect(url_for('reset_request'))

    question_text = dict(SECURITY_QUESTIONS).get(user.security_question)

    form = VerifyAnswerForm()
    if form.validate_on_submit():
        if user.check_security_answer(form.answer.data):
            session['reset_verified'] = True
            return redirect(url_for('reset_token'))
        else:
            flash('Resposta incorreta. Tente novamente.', 'danger')

    return render_template('verify_answer.html', title='Verificar Resposta', form=form, question=question_text)


@app.route("/reset_password/new", methods=['GET', 'POST'])
def reset_token():
    if 'reset_username' not in session or 'reset_verified' not in session:
        return redirect(url_for('reset_request'))

    username = session['reset_username']
    user = User.query.filter_by(username=username).first()
    if not user:
        session.clear()
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        session.clear()
        flash('A sua senha foi atualizada! Já pode fazer login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html', title='Nova Senha', form=form)


@app.route('/export_passwords')
@login_required
def export_passwords():
    passwords = PasswordEntry.query.filter_by(owner=current_user).all()
    if not passwords:
        flash('Você não tem senhas para exportar.', 'info')
        return redirect(url_for('dashboard'))

    decrypted_data = []
    for p in passwords:
        decrypted_data.append({
            'service_name': p.service_name,
            'username_or_email': p.username_or_email,
            'password': p.decrypt_password(current_user.encryption_key)  # Desencripta para exportar
        })

    json_data = json.dumps(decrypted_data, indent=4).encode('utf-8')
    fernet = Fernet(current_user.encryption_key)
    encrypted_data = fernet.encrypt(json_data)

    return Response(
        encrypted_data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": "attachment;filename=senhas_exportadas.json.enc"}
    )


@app.route('/import_passwords', methods=['GET', 'POST'])
@login_required
def import_passwords():
    form = ImportForm()
    if form.validate_on_submit():
        file = form.file.data
        encrypted_data = file.read()

        try:
            fernet = Fernet(current_user.encryption_key)
            decrypted_json = fernet.decrypt(encrypted_data)
            passwords_to_import = json.loads(decrypted_json.decode('utf-8'))

            count = 0
            for item in passwords_to_import:
                if 'service_name' in item and 'username_or_email' in item and 'password' in item:
                    entry = PasswordEntry(
                        service_name=item['service_name'],
                        username_or_email=item['username_or_email'],
                        owner=current_user
                    )

                    entry.encrypt_password(item['password'], current_user.encryption_key)
                    db.session.add(entry)
                    count += 1

            db.session.commit()
            flash(f'{count} senhas foram importadas com sucesso!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:

            db.session.rollback()
            flash('Erro ao importar o ficheiro. Verifique se o ficheiro está correto e não foi corrompido.', 'danger')

    return render_template('import_passwords.html', title='Importar Senhas', form=form)
