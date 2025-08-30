# Applied.
Simple curriculum app
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from passlib.hash import pbkdf2_sha256

# Minimal Flask setup for environments where multiprocessing or sockets may fail
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_curriculum.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SC_SECRET', 'dev-secret-key')

db = SQLAlchemy(app)

# ------------------ Models ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User')

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    course = db.relationship('Course')
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ Utility / Auth ------------------

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])

def login_user(user):
    session['user_id'] = user.id

def logout_user():
    session.pop('user_id', None)

# ------------------ Routes ------------------

base_html = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Smart Curriculum</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('index') }}">Smart Curriculum</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
        {% if g.user %}
          <li class="nav-item"><a class="nav-link">{{ g.user.name }} ({{ g.user.role }})</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {{ content|safe }}
</div>
</body>
</html>
'''

login_form = '''
<h3>Login</h3>
<form method="POST">
  <div class="mb-3">
    <label>Email</label>
    <input type="email" name="email" class="form-control" required>
  </div>
  <div class="mb-3">
    <label>Password</label>
    <input type="password" name="password" class="form-control" required>
  </div>
  <button type="submit" class="btn btn-primary">Login</button>
</form>
'''

@app.route('/')
def index():
    return render_template_string(base_html, content='<h3>Welcome to Smart Curriculum App</h3>')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template_string(base_html, content=login_form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

# ------------------ Startup ------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        defaults = [
            ('Admin User', 'admin@admin', 'admin', 'admin'),
            ('Demo Teacher', 'teacher@demo', 'teacher', 'teacher'),
            ('Demo Student', 'student@demo', 'student', 'student')
        ]
        for name, email, password, role in defaults:
            if not User.query.filter_by(email=email).first():
                db.session.add(User(
                    name=name,
                    email=email,
                    password_hash=pbkdf2_sha256.hash(password),
                    role=role
                ))
        db.session.commit()

    try:
        import wsgiref.simple_server
        httpd = wsgiref.simple_server.make_server('127.0.0.1', 5000, app)
        print('Server running on http://127.0.0.1:5000')
        httpd.serve_forever()
    except Exception as e:
        print(f'Cannot start server in this environment: {e}')
        print('Run this app in a standard Python environment or container with network support.')
