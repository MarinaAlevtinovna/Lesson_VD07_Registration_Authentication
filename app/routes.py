from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from app import models, forms, app, db, bcrypt
from app.models import User
from app.forms import RegistrationForm, LoginForm

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)  # Хеширование пароля
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Введены неверные данные', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html')


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        # Логика для обработки обновления профиля
        new_username = request.form.get("username")
        new_email = request.form.get("email")
        new_password = request.form.get("password")

        # Обновление данных текущего пользователя
        current_user.username = new_username
        current_user.email = new_email
        if new_password:
            current_user.set_password(new_password)  # Предполагается, что у вас есть метод для хеширования пароля
        db.session.commit()

        flash("Ваш профиль обновлен.", "success")
        return redirect(url_for("account"))  # Перенаправление на страницу профиля

    return render_template("edit_profile.html")


