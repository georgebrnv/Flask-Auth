from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['UPLOAD_FOLDER'] = 'static/files'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# LOGIN MANAGER SETUP
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        secured_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=16
        )
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=secured_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User with this Email does not exist. Please try again.')
        elif not check_password_hash(user.password, password):
            flash('Password is incorrect. Please try again.')
        else:
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", username=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for('login'))


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)


if __name__ == "__main__":
    app.run(debug=True)
