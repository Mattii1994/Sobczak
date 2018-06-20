from app import app, db
from models import *

from flask import render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_security import roles_required


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    first_name = StringField('Imie', validators=[InputRequired(), Length(max=25)])
    surname = StringField('Nazwisko', validators=[InputRequired(), Length(max=30)])
    email = StringField('Adres e-mail', validators=[InputRequired(), Email(message='Błędny adres email'), Length(max=50)])
    username = StringField('Nazwa użytkownika', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Hasło', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                if user.active == True:
                    login_user(user, remember=form.remember.data)
                    login_time = User.query.filter_by(username=form.username.data).first()
                    login_time.last_login = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    login_time.logged_in = True
                    db.session.commit()
                    return redirect(url_for('dashboard'))
        return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/register', methods=('POST', 'GET'))
def register():
    form = RegisterForm()
    roles = Role.query.all()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(first_name=form.first_name.data, surname=form.surname.data,
                        username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        current_create_user = User.query.filter_by(username=form.username.data).first()
        new_role = RolesUsers(user_id=current_create_user.id, role_id=request.form['permision'])
        db.session.add(new_role)
        db.session.commit()
        flash(u'Użytkownik ' + new_user.surname + ' ' + new_user.first_name + ' (' + new_user.username + ') został dodany.',
            'success')
        return redirect(url_for('user_manager'))

    return render_template('register.html', form=form, roles=roles)


@app.route('/dashboard')
def dashboard():
    return render_template('index3.html', name=current_user.first_name, surname=current_user.surname)


@app.route('/ref_noti')
@login_required
def refresh_noti():
    return render_template('noti_info_bar.html')

@app.route('/logout')
@login_required
def logout():
    logged = User.query.filter_by(username=current_user.username).first()
    logged.logged_in = False
    db.session.commit()
    logout_user()

    return redirect(url_for('login'))


@app.route('/users_groups')
@login_required
def users_groups():
    roles = Role.query.all()
    count_of_users = db.session.query(RolesUsers.role_id, db.func.count(RolesUsers.user_id)).group_by(RolesUsers.role_id).all()
    return render_template('groups.html', name=current_user.first_name, surname=current_user.surname,
                           roles=roles, count_of_users=count_of_users)


@app.route('/user_delete')
@login_required
def user_delete():
    user = User.query.filter_by(id=request.form['delete']).first()
    db.session.delete(user)
    db.session.commit()
    flash(u'Użytkownik ' + user.surname + ' ' + user.first_name + ' (' + user.username + ') został pomyślnie usunięty.', 'success')

    return redirect(url_for('user_manager'))

@app.route('/add_group', methods=['POST', 'GET'])
@login_required
def add_group():

    if request.method == 'POST':
        temp = request.form['group_name'].lower()
        exist = Role.query.filter_by(name=temp).count()
        if exist == 0:
            flash(u'Podana grupa już istnieje!', 'danger')
            redirect(url_for('add_group'))

        if request.form['description'] == '' or len(request.form['description'] <= 10):
            flash(u'Opis grupy jest za krótki.', 'danger')
            redirect(url_for('add_group'))
        else:
            new_role = Role(name=request.form['group_name'], description=request.form['description'])
            db.session.add(new_role)
            db.session.commit()
            flash(u'Dodano grupę' + ' ' + request.form['group_name'], 'success')
            redirect(url_for('users_groups'))

    return render_template('add_group.html', name=current_user.first_name, surname=current_user.surname)


@app.route('/user_manager')
@login_required
def user_manager():
    users = User.query.all()
    role = RolesUsers.query.all()
    sys_roles = Role.query.all()
    return render_template('users_manager.html', name=current_user.first_name, surname=current_user.surname,
                           users=users, role=role, sys_roles=sys_roles)


@app.route('/user_manager_search', methods=['POST', 'GET'])
@login_required
def user_manager_search():
    role = RolesUsers.query.all()
    sys_roles = Role.query.all()

    temp = request.form['search']
    new_temp = ''
    if temp == '':
       return redirect(url_for('user_manager'))
    else:
        i = 0
        temp = temp.title()

        for c in temp:
            if i == 0:
                new_temp += c
            else:
                new_temp += ' '.upper()
        else:
            i += 1

        new_temp = new_temp.split()
        for x in new_temp:
            finds_users = User.query.filter(User.first_name.like(x) | User.surname.like(x))

    return render_template('users_manager.html', name=current_user.first_name, surname=current_user.surname, temp=new_temp,
                           users=finds_users, role=role, sys_roles=sys_roles)


@app.route('/sensors_list')
@login_required
def sensors_list():
    sensors = Sensor.query.all()
    rooms = Rooms.query.all()

    return render_template('users_manager.html', name=current_user.first_name, surname=current_user.surname,
                           sensors=sensors, rooms=rooms)


@app.route('/sensors_list_search')
@login_required
def sensors_list_search():
    temp = request.form['search']
    new_temp = ''
    if temp == '':
        return redirect(url_for('sensors_list'))
    else:
        i = 0
        temp = temp.title()

        for c in temp:
            if i == 0:
                new_temp += c
            else:
                new_temp += ' '.upper()
        else:
            i += 1

        new_temp = new_temp.split()
        for x in new_temp:
            finds_users = User.query.filter(User.first_name.like(x) | User.surname.like(x))


@app.route('/add_sensor')
@login_required
def add_sensor():
    return render_template('users_manager.html', name=current_user.first_name, surname=current_user.surname)


@app.route('/sensor')
@login_required
def sensor():
    return render_template('sensor.html', name=current_user.first_name, surname=current_user.surname)
