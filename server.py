from flask import Flask, request, render_template, flash, session, redirect
from mysqlconnection import MySQLConnector
# imports the Bcrypt module
from flask_bcrypt import Bcrypt
import re


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
app.secret_key = 'SecretKey'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'thewall')
# this will load a page that has 2 forms one for registration and login




@app.route('/', methods=['GET'])
def index():

    return render_template('index.html')



@app.route('/register')
def register():

    return render_template('register.html')



@app.route('/login_portal')
def login_portal():

    return render_template('login_portal.html')




@app.route('/create_user', methods=['POST'])
def create_user():

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if len(first_name) < 2:
        flash('First name must least be two characters')
        return redirect('/register')

    elif first_name.isalpha() != True:
        flash('First name must contain only letters')
        return redirect('/register')

    elif len(last_name) < 2:
        flash('last name must least be two characters')
        return redirect('/register')

    elif last_name.isalpha() != True:
        flash('last name must contain only letters')
        return redirect('/register')

    elif len(email) < 3:
        flash('Insert an email address')
        return redirect('/register')

    elif not EMAIL_REGEX.match(email):
        flash('Please enter valid Email address')
        return redirect('/register')

    elif len(password) < 8:
        flash('Password must be longer than 8 characters')
        return redirect('/register')

    elif len(confirm_password) < 1:
        flash('Must confirm password')
        return redirect('/register')

    elif confirm_password != password:
        flash('Password does not match')
        return redirect('/register')

    else:
        pw_hash = bcrypt.generate_password_hash(password)

    insert_query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW() )"

    query_data = {
        'first_name':first_name,
        'last_name':last_name,
        'email': email,
        'pw_hash': pw_hash
    }
    mysql.query_db(insert_query, query_data)

    flash('Thank you for registering! Please log in')
    return redirect('/login_portal')


@app.route('/login', methods=['POST'])
def login():

    email = request.form['email']
    password = request.form['password']

    if len(email) < 1:
        flash('Insert an email address')
        return redirect('/login_portal')

    elif not EMAIL_REGEX.match(email):
        flash('Please enter valid Email address')
        return redirect('/login_portal')

    elif len(password) < 8:
        flash('Password must be longer than 8 characters')
        return redirect('/login_portal')

    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data) # user will be returned in a list

    # print user


# NEED TO MAKE A CONDITION THAT CHECKS IF THE EMAIL IS IN THE DATABASE OR NOT.
    # if request.form['email'] is not mysql.query_db(user_query, query_data):
    #     flash('Email not in database. Please register')
    #     return redirect('/login_portal')



    current_user = "SELECT id, first_name, last_name FROM users WHERE email = :email LIMIT 1"
    session['current_user'] = mysql.query_db(current_user, query_data)
    logged_user = session['current_user']
    # print logged_user

    if bcrypt.check_password_hash(user[0]['pw_hash'], password):
        return render_template('theWall.html', logged_user=logged_user)
    else:
        flash('Password or email incorrect')
        return redirect('/login_portal')




@app.route('/wall')
def wall():

    if 'current_user' not in session:
        flash('Must log in first')
        return redirect('/')

    return render_template('theWall.html')




@app.route('/store/<id>/message', methods=['POST'])
def store_message(id):

    message = request.form['message']

    query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW() )"

    data = {
        'user_id': id,
        'message': message
    }

    mysql.query_db(query, data)

    return redirect('/post_message')




@app.route('/post_message')
def post_message():

    query = 'SELECT users.id, messages.id, users.first_name, users.last_name, messages.message, messages.created_at, messages.updated_at FROM users JOIN messages on users.id = messages.user_id ORDER BY messages.created_at desc'

    session['messages'] = mysql.query_db(query)

    return redirect('/wall')




@app.route('/store/<id>/comment', methods=['POST'])
def store_comment(id):

    return redirect('/post_comment')

@app.route('/post_comment')
def post_comment():
    
    return redirect('/wall')




@app.route('/logout')
def logout():
    session.pop('current_user')
    flash('You have been logged out successfully')
    return redirect('/')

@app.route('/clear')
def clear():
    session.pop('messages')

    return redirect('/login_portal')


app.run(debug=True)
