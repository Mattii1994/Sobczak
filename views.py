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
@login_required
def dashboard():

    sensors = Sensor.query.all()

    return render_template('index3.html', name=current_user.first_name, surname=current_user.surname, sensors=sensor)


@app.route('/room_info/<room>')
@app.route('/room_info/<path:room>')
@login_required
def room_info(room):

    room_information = Rooms.query.filter_by(room_number=room).first()
    sensor = Sensor.query.filter_by(id_room=room_information.id_room).first()

    return render_template('room_info.html', name=current_user.first_name, surname=current_user.surname, sensors=sensor,
                           room_information=room_information)


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
    flash(u'Użytkownik ' + user.surname + ' ' + user.first_name + ' (' + user.username + ') został pomyślnie usunięty.',
          'success')

    return redirect(url_for('user_manager'))


@app.route('/add_group', methods=['POST', 'GET'])
@login_required
def add_group():

    if request.method == 'POST':
        temp = request.form['group_name'].lower()
        exist = Role.query.filter_by(name=temp).count()
        if exist != 0:
            flash(u'Podana grupa już istnieje!', 'danger')
            redirect(url_for('add_group'))

        if request.form['description'] == '' or len(request.form['description']) < 10:
            flash(u'Opis grupy jest za krótki.', 'danger')
            redirect(url_for('add_group'))
        else:
            new_role = Role(name=request.form['group_name'], description=request.form['description'])
            db.session.add(new_role)
            db.session.commit()
            flash(u'Dodano grupę' + ' ' + request.form['group_name'], 'success')
            redirect(url_for('users_groups'))

    return render_template('add_group.html', name=current_user.first_name, surname=current_user.surname)


@app.route('/notification', methods=['POST', 'GET'])
@login_required
def notification():

    notifications = Notification.query.all
    notification_dev = Sensor.query.all()
    room = Rooms.query.all()

    return render_template('notifications.html', notifications=notifications, notification_dev=notification_dev,
                           room=room)


@app.route('/delete_noti', methods=['POST', 'GET'])
def delete_noti():
    noti_to_delete = Notification.query.filter_by(id=request.form['noti_delete']).first()
    db.session.delete(noti_to_delete)
    db.session.commit()

    return redirect(url_for('notification'))


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


@app.route('/workers_list')
@login_required
def workers_list():
    users = User.query.all()
    workers = Worker.query.all()
    rooms = Rooms.query.all()

    return render_template('workers_list.html', name=current_user.first_name, surname=current_user.surname,
                           users=users, workers=workers, rooms=rooms)


@app.route('/workers_list_search', methods=['POST', 'GET'])
@login_required
def workers_list_search():
    role = RolesUsers.query.all()
    sys_roles = Role.query.all()

    temp = request.form['search']
    new_temp = ''
    if temp == '':
       return redirect(url_for('workers_list'))
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

    return render_template('workers_list.html', name=current_user.first_name, surname=current_user.surname, temp=new_temp,
                           users=finds_users, role=role, sys_roles=sys_roles)


@app.route('/assign_worker')
@login_required
def assign_worker():
    workers = Worker.query.all()
    users = User.query.all()
    rooms = Rooms.query.all()

    if request.method == 'POST':
        assign = Worker

    return render_template('assign_worker.html',name=current_user.first_name, surname=current_user.surname, workers=workers,
                           users=users, rooms=rooms)
    


@app.route('/account_info')
@login_required
def account_info():
    r_user = RolesUsers.query.filter_by(user_id=current_user.id).first()
    role = Role.query.filter_by(id=r_user.role_id).first()
    return render_template('account_info.html', name=current_user.first_name, surname=current_user.surname, role=role.name)


@app.route('/sensors_list')
@login_required
def sensors_list():
    sensors = Sensor.query.all()
    rooms = Rooms.query.all()

    return render_template('sensors_list.html', name=current_user.first_name, surname=current_user.surname,
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


@app.route('/add_sensor', methods=['POST', 'GET'])
@login_required
def add_sensor():
    rooms = Rooms.query.all()

    if request.method == 'POST':
        if request.form['button'] == '+ Dodaj sensor':
            temp = request.form['ip']
            exist = Sensor.query.filter_by(ip_address=temp).count()
            if exist != 0:
                flash(u'Adres IP jest już zajęty!', 'danger')
                redirect(url_for('add_sensor'))
            new_sensor = Sensor(sensor_brand=request.form['sensor_brand'], sensor_name=request.form['sensor_name'],
                                serial_number=request.form['serial_number'], ip_address=request.form['ip'],
                                id_room=request.form['id_room'], )
            db.session.add(new_sensor)
            db.session.commit()
            flash(u'Dodano czujnik' + ' ' + request.form['group_name'], 'success')
            redirect(url_for('users_groups'))

        elif request.form['button'] == 'Sprawdz':
            import os
            sensor_ip = request.form['ip']
            response = os.system("ping -c 1 " + sensor_ip)

            return render_template('check.html', response=response, sensor_ip=sensor_ip)

    return render_template('add_sensor.html', name=current_user.first_name, surname=current_user.surname, rooms=rooms)


@app.route('/sensor')
@login_required
def sensor():
    sensors = Sensor.query.all()
    rooms = Rooms.query.all()

    return render_template('sensor.html', name=current_user.first_name, surname=current_user.surname, sensors=sensors, rooms=rooms)


@app.route('/edit_sensor', methods=['POST', 'GET'])
@login_required
def edit_sensor():
    edited_sensor = Sensor.query.filter_by(id_elem=request.form['edit']).first()
    rooms = Rooms.query.all()

    if request.method == 'POST':
        edited_sensor.sensor_brand = request.form['sensor_brand']
        edited_sensor.sensor_name=request.form['sensor_name']
        edited_sensor.serial_number=request.form['serial_number']
        edited_sensor.ip_address=request.form['ip']
        edited_sensor.id_room=request.form['id_room']
        edited_sensor.mount_date = request.form['date']
        db.session.commit()
        return redirect(url_for(sensors_list))

    return render_template('edit_sensor.html')


@app.route('/delete_sensor')
@login_required
def sensor_delete():
    sensor_to_delete = Sensor.query.filter_by(id_elem=request.form['delete']).first()

    db.session.delete(sensor_to_delete)
    db.session.commit()
    flash(u'Sensor został pomyślnie usunięty.', 'success')

    return redirect(url_for('sensors_list'))


@app.route('/reviews')
@login_required
def review_sensor_list():

    return render_template('reviews.html', name=current_user.first_name, surname=current_user.surname)


@app.route('/handler', methods=['POST'])
def sensor_signal_handler():
    if request.method == 'POST':
        ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        change_state = Sensor.query.filter_by(ip_address=ip).first()
        if change_state is True:
            pass
        else:
            change_state.signal = True
            redirect(url_for('dashboard'))
        print('OK')
    return 'OK'


@app.route('/check_sensor_alive', methods=['POST', 'GET'])
@login_required
def check_sensor_alive():
    import os
    sensor_ip = request.form['ip']

    response = os.system("ping -c 1 " + sensor_ip)

    return render_template('check.html', response=response, sensor_ip=sensor_ip)


@app.route('/check_sensors_alive')
@login_required
def check_sensors_alive():
    import os
    sensors_ip = Sensor.query.all()
    for ip in sensors_ip:
        response = os.system("ping -c 5 " + ip)
        if response == 0:
            ip.alive = True
        else:
            ip.alive = False

        db.session.commit()

    return ip.alive

"""Konwersja SVG na JPG"""

from argparse import ArgumentParser
import subprocess
import os.path


def main():
    args = parse_args()
    if not args.out:
        args.out = os.path.splitext(args.file)[0] + '.png'
    convert_with_rsvg(args)


def convert_with_cairosvg_simple(args):
    # import cairocffi as cairo
    from cairosvg import svg2png
    svg2png(open(args.file, 'rb').read(), write_to=open(args.out, 'wb'))


def convert_with_cairosvg_sizes(args):
    from cairosvg.surface import PNGSurface
    width, height = args.size.split('x')
    with open(args.file, 'rb') as svg_file:
        PNGSurface.convert(
            bytestring=svg_file.read(),
            width=width,
            height=height,
            write_to=open(args.out, 'wb')
            )

def convert_with_rsvg(args):
    import cairo
    import rsvg

    width, height = args.size.split('x')
    img =  cairo.ImageSurface(cairo.FORMAT_ARGB32, int(width), int(height))
    ctx = cairo.Context(img)
    handler= rsvg.Handle(args.file)
    handler.render_cairo(ctx)
    img.write_to_png(args.out)


def convert_with_inkscape(args):
    try:
        inkscape_path = subprocess.check_output(["which", "inkscape"]).strip()
    except subprocess.CalledProcessError:
        print("ERROR: You need inkscape installed to use this script.")
        exit(1)

    export_width, export_height = args.size.split('x')

    args = [
        inkscape_path,
        "--without-gui",
        "-f", args.file,
        "--export-area-page",
        "-w", export_width,
        "-h", export_height,
        "--export-png=" + args.out
    ]
    print(args)
    subprocess.check_call(args)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help="SVG file to open")
    parser.add_argument('-s', '--size', required=True, help="target size to render")
    parser.add_argument('-o', '--out', help="Destination file")
    return parser.parse_args()
