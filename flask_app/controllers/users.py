import datetime
import math
import random
import smtplib
from flask_app import app
from flask_app.models.user import User
from flask_app.config.mysqlconnection import connectToMySQL

from flask import render_template, redirect, session, request, flash
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

from .env import ADMINEMAIL
from .env import PASSWORD


# Invalid Route
@app.errorhandler(404)
def invalid_route(e):
    return render_template('404.html')


# Intro
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/logout')


# Register Route
@app.route('/registerPage')
def registerPage():
    if 'user_id' in session:
        return redirect('/')
    return render_template('signup.html')


# Register Control Form
@app.route('/register', methods=['POST'])
def register():
    if 'user_id' in session:
        return redirect('/')

    if User.get_user_by_email(request.form):
        flash('This email already exists', 'emailRegister')
        return redirect(request.referrer)

    if not User.validate_user(request.form):
        flash('You have some errors! Fix them to sign Up', 'registrationFailed')
        return redirect(request.referrer)
    string = '0123456789ABCDEFGHIJKELNOPKQSTUV'
    vCode = ""
    length = len(string)
    for i in range(8):
        vCode += string[math.floor(random.random() * length)]
    verificationCode = vCode

    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': bcrypt.generate_password_hash(request.form['password']),
        'isVerified': 0,
        'verificationCode': verificationCode
    }
    User.save(data)

    LOGIN = ADMINEMAIL
    TOADDRS = request.form['email']
    SENDER = ADMINEMAIL
    SUBJECT = 'Verify Your Email'
    msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n"
           % ((SENDER), "".join(TOADDRS), SUBJECT))
    msg += f'Use this verification code to activate your account: {verificationCode}'
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.set_debuglevel(1)
    server.ehlo()
    server.starttls()
    server.login(LOGIN, PASSWORD)
    server.sendmail(SENDER, TOADDRS, msg)
    server.quit()

    user = User.get_user_by_email(data)
    if user:
        session['user_id'] = user['id']
        return redirect('/verify/email')
    else:
        flash('User not found', 'userNotFound')
        return redirect(request.referrer)


# Verify Email Route
@app.route('/verify/email')
def verifyEmail():
    if 'user_id' not in session:
        return redirect('/')
    data = {
        'user_id': session['user_id']
    }
    user = User.get_user_by_id(data)
    if user['isVerified'] == 1:
        return redirect('/dashboard')
    return render_template('verifyEmail.html', loggedUser=user)


# Email Validation
@app.route('/activate/account', methods=['POST'])
def activateAccount():
    if 'user_id' not in session:
        return redirect('/')
    data = {
        'user_id': session['user_id']
    }
    user = User.get_user_by_id(data)
    if user['isVerified'] == 1:
        return redirect('/dashboard')

    if not request.form['verificationCode']:
        flash('Verification Code is required', 'wrongCode')
        return redirect(request.referrer)

    if request.form['verificationCode'] != user['verificationCode']:
        string = '0123456789'
        vCode = ""
        length = len(string)
        for i in range(8):
            vCode += string[math.floor(random.random() * length)]
        verificationCode = vCode
        dataUpdate = {
            'verificationCode': verificationCode,
            'user_id': session['user_id']
        }
        User.updateVerificationCode(dataUpdate)
        LOGIN = ADMINEMAIL
        TOADDRS = user['email']
        SENDER = ADMINEMAIL
        SUBJECT = 'Verify Your Email'
        msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n"
               % ((SENDER), "".join(TOADDRS), SUBJECT))
        msg += f'Use this verification code to activate your account: {verificationCode}'
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.set_debuglevel(1)
        server.ehlo()
        server.starttls()
        server.login(LOGIN, PASSWORD)
        server.sendmail(SENDER, TOADDRS, msg)
        server.quit()

        flash('Verification Code is wrong. We just sent you a new one', 'wrongCode')
        return redirect(request.referrer)

    User.activateAccount(data)
    return redirect('/dashboard')


# Log In Route
@app.route('/loginPage')
def loginPage():
    if 'user_id' in session:
        return redirect('/')
    return render_template('login.html')


# Control Log In Form
@app.route('/login', methods=['POST'])
def login():
    if 'user_id' in session:
        return redirect('/')
    if not User.get_user_by_email(request.form):
        flash('This email doesnt appear to be in our system! Try another one!', 'emailLogin')
        return redirect(request.referrer)

    user = User.get_user_by_email(request.form)
    if user:
        if not bcrypt.check_password_hash(user['password'], request.form['password']):
            flash('Wrong Password', 'passwordLogin')
            return redirect(request.referrer)

    session['user_id'] = user['id']

    return redirect('/verify/email')


# Edit Post Form Route
@app.route('/edit/profile')
def edit_profile():
    if 'user_id' in session:
        data = {
            'user_id': session['user_id'],
        }
        loggedUser = User.get_user_by_id(data)
        if loggedUser['isVerified'] == 0:
            return redirect('/verify/email')
        return render_template('editProfile.html', loggedUser=loggedUser)
    return redirect('/profile')


# Update Profile Form
@app.route('/editProfile', methods=['POST'])
def editProfile():
    if 'user_id' in session:
        if not User.validate_user_profile(request.form):
            flash('You have some errors!')
            return redirect(request.referrer)
        data = {
            'user_id': session['user_id'],
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name']
        }
        loggedUser = User.get_user_by_id(data)
        if loggedUser['isVerified'] == 0:
            return redirect('/verify/email')
        User.update(data)
        return redirect(request.referrer)
    return redirect(request.referrer)


# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'user_id': session['user_id']
    }
    loggedUser = User.get_user_by_id(data)
    if loggedUser['isVerified'] == 0:
        return redirect('/verify/email')
    liked_posts = User.get_user_liked_posts(data)
    faved_posts = User.get_user_faved_posts(data)
    return (render_template('dashboard.html', posts=Post.get_all(data), loggedUser=loggedUser,
                            liked_posts=liked_posts, faved_posts=faved_posts))


# View Logged User Profile
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'user_id': session['user_id']
    }
    loggedUser = User.get_user_by_id(data)
    if loggedUser['isVerified'] == 0:
        return redirect('/verify/email')
    posts = Post.get_all_user_posts(data)
    no_posts = len(Post.get_all_user_posts(data))
    followers = len(User.get_followers(data))
    followings = len(User.get_followings(data))
    faved_posts = User.get_user_faved_posts(data)
    liked_posts = User.get_user_liked_posts(data)
    return render_template('profile.html', posts=posts, loggedUser=loggedUser, no_posts=no_posts,
                           followers=followers, followings=followings, faved_posts=faved_posts,
                           liked_posts=liked_posts)


# View liked posts
@app.route('/liked')
def likedPosts():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'user_id': session['user_id']
    }
    loggedUser = User.get_user_by_id(data)
    if loggedUser['isVerified'] == 0:
        return redirect('/verify/email')
    posts = Post.user_liked_posts(data)
    no_posts = len(Post.get_all_user_posts(data))
    followers = len(User.get_followers(data))
    followings = len(User.get_followings(data))
    faved_posts = User.get_user_faved_posts(data)
    liked_posts = User.get_user_liked_posts(data)
    return render_template('likes.html', posts=posts, loggedUser=loggedUser, no_posts=no_posts,
                           followers=followers, followings=followings, liked_posts=liked_posts,
                           faved_posts=faved_posts)


# View liked posts
@app.route('/faved')
def favedPosts():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'user_id': session['user_id']
    }
    loggedUser = User.get_user_by_id(data)
    if loggedUser['isVerified'] == 0:
        return redirect('/verify/email')
    posts = Post.user_faved_posts(data)
    no_posts = len(Post.get_all_user_posts(data))
    followers = len(User.get_followers(data))
    followings = len(User.get_followings(data))
    liked_posts = User.get_user_liked_posts(data)
    faved_posts = User.get_user_faved_posts(data)
    return render_template('saved.html', posts=posts, loggedUser=loggedUser, no_posts=no_posts,
                           followers=followers, followings=followings, liked_posts=liked_posts,
                           faved_posts=faved_posts)


@app.route('/profile/followers')
def profileFollowers():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'user_id': session['user_id']
    }
    loggedUser = User.get_user_by_id(data)
    if loggedUser['isVerified'] == 0:
        return redirect('/verify/email')
    posts = Post.get_all_user_posts(data)
    no_posts = len(Post.get_all_user_posts(data))
    no_followers = len(User.get_followers(data))
    followings = User.get_followings(data)
    no_followings = len(User.get_followings(data))
    followers = User.get_followers(data)
    return render_template('followers.html', posts=posts, loggedUser=loggedUser, no_posts=no_posts,
                           followers=followers, followings=followings, folls=no_followers,
                           fwings=no_followings, followed = User.get_followers_id(data))


@app.route('/profile/followings')
def profileFollowings():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'user_id': session['user_id']
    }
    loggedUser = User.get_user_by_id(data)
    if loggedUser['isVerified'] == 0:
        return redirect('/verify/email')
    posts = Post.get_all_user_posts(data)
    no_posts = len(Post.get_all_user_posts(data))
    no_followers = len(User.get_followers(data))
    followings = User.get_followings(data)
    no_followings = len(User.get_followings(data))
    followers = User.get_followers(data)
    return render_template('followings.html', posts=posts, loggedUser=loggedUser, no_posts=no_posts,
                           followers=followers, followings=followings, folls=no_followers,
                           fwings=no_followings, followed = User.get_followers_id(data))


# View User
@app.route('/user/<int:id>')
def viewUser(id):
    if 'user_id' in session:
        data = {
            'user_id': session['user_id'],
            'person_id': id
        }
        loggedUser = User.get_user_by_id(data)
        if loggedUser['isVerified'] == 0:
            return redirect('/verify/email')
        person = User.get_person_by_id(data)
        likes = Post.get_all_post_likes(data)
        no_posts = len(Post.get_all_person_posts(data))
        followers = len(User.get_followers_user(data))
        followings = len(User.get_followings_user(data))
        return render_template('user.html', loggedUser=loggedUser, person=person,
                               posts=Post.get_all_person_posts(data), likes=likes,
                               liked_posts=User.get_user_liked_posts(data),
                               faved_posts=User.get_user_faved_posts(data),
                               followed=User.get_follow_by_userid(data),
                               followers=followers, followings=followings, no_posts=no_posts)
    return redirect('/')


# Follow user
@app.route('/follow/user/<int:id>')
def follow(id):
    if 'user_id' in session:
        data = {
            'user_id': session['user_id'],
            'person_id': id
        }
        loggedUser = User.get_user_by_id(data)
        person = User.get_person_by_id(data)
        User.follow(data)
        return redirect(request.referrer)


# Unfollow user
@app.route('/unfollow/user/<int:id>')
def unfollow(id):
    if 'user_id' in session:
        data = {
            'user_id': session['user_id'],
            'person_id': id
        }
        loggedUser = User.get_user_by_id(data)
        person = User.get_person_by_id(data)
        User.unfollow(data)
        return redirect(request.referrer)


# Search Route
@app.route('/searchUser')
def searchPage():
    if 'user_id' in session:
        return render_template('search.html')
    return redirect('/')


@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' in session:
        if request.method == "POST":
            data = {
                'user_id': session['user_id'],
                'search_query': request.form['search_query']
            }

            results = connectToMySQL('pulse_db').query_db(
                f"SELECT * FROM users WHERE first_name LIKE '%{data['search_query']}%' OR "
                f"last_name "
                f"LIKE '%{data['search_query']}%';")
            users = []
            if results:
                for user in results:
                    users.append(user)
                return render_template('search.html', results=users,
                                       loggedUser=User.get_user_by_id(data),
                                       search=request.form['search_query'])
            return render_template('search.html', results=users,
                                   loggedUser=User.get_user_by_id(data),
                                   search=request.form['search_query'])
    return redirect('/search')


# =========================================================================================
# ================================ MESSAGES =================================


@app.route('/inbox')
def loadInbox():
    if 'user_id' in session:
        data = {
            'user_id': session['user_id']
        }
        loggedUser = User.get_user_by_id(data)
        inboxes = Message.inboxes(data)
        return render_template('inbox.html', loggedUser=loggedUser, inboxes=inboxes)
    return redirect('/logout')


@app.route('/notifications')
def loadNotifications():
    if 'user_id' in session:
        data = {
            'user_id': session['user_id']
        }
        loggedUser = User.get_user_by_id(data)
        notifications = User.get_notifications(data)
        print("=============================================")
        print(notifications)
        print("=============================================")
        return render_template('notifications.html', loggedUser=loggedUser,
                               notifications=notifications)
    return redirect('/logout')


# @app.route('/messages/<int:id>')
# def loadMessages(id):
#     if 'user_id' in session:
#         data = {
#             'user_id': session['user_id'],
#             'person_id': id
#         }
#         loggedUser = User.get_user_by_id(data)
#         person = User.get_person_by_id(data)
#         messages = Message.get_messages_by_user(data)
#         return render_template('test.html', loggedUser=loggedUser, person=person,
#                                messages=messages)
#     return redirect('/logout')

@app.route('/messages/<int:id>')
def loadMessages(id):
    if 'user_id' in session:
        # Fetch the person's information and pass it to the template
        data = {
            'user_id': session['user_id'],
            'person_id': id
           }
        loggedUser = User.get_user_by_id(data)
        person = User.get_person_by_id({'person_id': id})
        messages = Message.get_messages_by_user(data)
        return render_template('messages.html', loggedUser=loggedUser, person=person,
                               messages=messages)
    return redirect('/logout')


# Add Comment
@app.route('/add/message/<int:id>', methods=['POST'])
def message(id):
    if 'user_id' not in session:
        return redirect('/')
    data = {
        'user_id': session['user_id'],
        'person_id': id,
        'content': request.form['content']
    }
    loggedUser = User.get_user_by_id(data)
    person = User.get_person_by_id(data)
    Message.save(data)
    return redirect(request.referrer)


# Log Out
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/loginPage')
