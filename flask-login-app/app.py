from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from wtforms import Form, StringField, PasswordField, validators

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'your_mysql_user'
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
app.config['MYSQL_DB'] = 'user_database'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Registration Form
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')

# Login Form
class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])

# Home Page
@app.route('/')
def home():
    return render_template('login.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Insert user into the database
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(username, password) VALUES(%s, %s)", (username, password))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('home'))

    return render_template('register.html', form=form)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_candidate = form.password.data

        # Fetch user from database
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
        
        if result > 0:
            user_data = cur.fetchone()
            password = user_data['password']

            # Check password
            if bcrypt.check_password_hash(password, password_candidate):
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', form=form, error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', form=form, error=error)

        cur.close()

    return render_template('login.html', form=form)

# Dashboard Route (only accessible if logged in)
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        return 'Welcome, ' + session['username']
    return redirect(url_for('login'))

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
