from flask import Flask, render_template_string, request, redirect, session, flash, url_for, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "super-secure-key")
csrf = CSRFProtect(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg', 'jpeg'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database initialization
def init_db():
    with sqlite3.connect('secure_app.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            bio TEXT DEFAULT ''
        )''')

init_db()

# Flask-WTF Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3)])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3)])
    submit = SubmitField('Signup')

class CommentForm(FlaskForm):
    comment = StringField('Comment', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Post')

class BioForm(FlaskForm):
    bio = StringField('Bio', validators=[DataRequired(), Length(min=3, max=200)])
    submit = SubmitField('Update')

class UploadForm(FlaskForm):
    file = FileField('Upload File')
    submit = SubmitField('Upload')

# Helper function
def base_template(content):
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Shop</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="container mt-5">
        <div class="card p-4 shadow-lg">
            {content}
        </div>
    </body>
    </html>
    '''

@app.route('/')
def index():
    if 'username' in session:
        content = f'''
            <h2>Hello, {session['username']}</h2>
            <a class="btn btn-warning" href="/product">Product Page</a>
            <a class="btn btn-info" href="/csrf-demo">Edit Bio</a>
            <a class="btn btn-secondary" href="/upload">Upload File</a>
            <a class="btn btn-danger" href="/logout">Logout</a>
        '''
    else:
        content = '''
            <h2>Welcome to Secure Shop</h2>
            <a class="btn btn-success" href="/signup">Signup</a>
            <a class="btn btn-primary" href="/login">Login</a>
        '''
    return render_template_string(base_template(content))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        try:
            with sqlite3.connect('secure_app.db') as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            flash("Signup successful. Please login.", "success")
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
    content = '''
        <h2>Signup</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.username.label }} {{ form.username(class_='form-control') }}<br>
            {{ form.password.label }} {{ form.password(class_='form-control') }}<br>
            {{ form.submit(class_='btn btn-success') }}
        </form>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, msg in messages %}<div class="alert alert-{{ category }}">{{ msg }}</div>{% endfor %}
          {% endif %}
        {% endwith %}
    '''
    return render_template_string(base_template(content), form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        with sqlite3.connect('secure_app.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
        if user and check_password_hash(user[0], password):
            session['username'] = username
            return redirect('/')
        else:
            flash("Invalid credentials", "danger")
    content = '''
        <h2>Login</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.username.label }} {{ form.username(class_='form-control') }}<br>
            {{ form.password.label }} {{ form.password(class_='form-control') }}<br>
            {{ form.submit(class_='btn btn-primary') }}
        </form>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, msg in messages %}<div class="alert alert-{{ category }}">{{ msg }}</div>{% endfor %}
          {% endif %}
        {% endwith %}
    '''
    return render_template_string(base_template(content), form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/product', methods=['GET', 'POST'])
def product():
    form = CommentForm()
    comment = ''
    if form.validate_on_submit():
        comment = form.comment.data
    content = '''
        <h2>Product Page</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.comment.label }} {{ form.comment(class_='form-control') }}<br>
            {{ form.submit(class_='btn btn-info') }}
        </form>
        {% if comment %}<div class="mt-3 alert alert-secondary">Comment: {{ comment|e }}</div>{% endif %}
        <a class="btn btn-secondary" href="/">Back</a>
    '''
    return render_template_string(base_template(content), form=form, comment=comment)

@app.route('/csrf-demo', methods=['GET', 'POST'])
def csrf_demo():
    form = BioForm()
    message = ''
    if 'username' not in session:
        return redirect('/login')
    if form.validate_on_submit():
        bio = form.bio.data
        with sqlite3.connect('secure_app.db') as conn:
            conn.execute("UPDATE users SET bio=? WHERE username=?", (bio, session['username']))
        message = "Bio updated successfully."
    content = '''
        <h2>Edit Bio</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.bio.label }} {{ form.bio(class_='form-control') }}<br>
            {{ form.submit(class_='btn btn-warning') }}
        </form>
        {% if message %}<div class="alert alert-success mt-3">{{ message }}</div>{% endif %}
        <a class="btn btn-secondary" href="/">Back</a>
    '''
    return render_template_string(base_template(content), form=form, message=message)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = UploadForm()
    message = ''
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            message = f"Uploaded file: {filename}"
    content = '''
        <h2>Upload a File</h2>
        <form method="POST" enctype="multipart/form-data">
            {{ form.hidden_tag() }}
            {{ form.file.label }} {{ form.file(class_='form-control') }}<br>
            {{ form.submit(class_='btn btn-dark') }}
        </form>
        {% if message %}<div class="alert alert-success mt-3">{{ message }}</div>{% endif %}
        <a class="btn btn-secondary" href="/">Back</a>
    '''
    return render_template_string(base_template(content), form=form, message=message)

@app.route('/uploads/<path:filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
