import datetime
import math
import random
import smtplib
from flask_app import app
from flask_app.models.user import User
from flask_app.config.mysqlconnection import connectToMySQL
import requests

from flask import render_template, redirect, session, request, flash
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

from .env import ADMINEMAIL
from .env import PASSWORD


# Invalid Route
@app.errorhandler(404)
def invalid_route(e):
    return render_template("404.html")


# Intro
@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/logout")


# Register Route
@app.route("/registerPage")
def registerPage():
    if "user_id" in session:
        return redirect("/")
    return render_template("signup.html")


# Register Control Form
@app.route("/register", methods=["POST"])
def register():
    if "user_id" in session:
        return redirect("/")

    if User.get_user_by_email(request.form):
        flash("This email already exists", "emailRegister")
        return redirect(request.referrer)

    if not User.validate_user(request.form):
        flash("You have some errors! Fix them to sign Up", "registrationFailed")
        return redirect(request.referrer)
    string = "0123456789ABCDEFGHIJKELNOPKQSTUV"
    vCode = ""
    length = len(string)
    for i in range(6):
        vCode += string[math.floor(random.random() * length)]
    verificationCode = vCode

    data = {
        "first_name": request.form["first_name"],
        "last_name": request.form["last_name"],
        "email": request.form["email"],
        "password": bcrypt.generate_password_hash(request.form["password"]),
        "isVerified": 0,
        "verificationCode": verificationCode,
    }
    User.save(data)

    LOGIN = ADMINEMAIL
    TOADDRS = request.form["email"]
    SENDER = ADMINEMAIL
    SUBJECT = "Verify Your Email"
    msg = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (
        (SENDER),
        "".join(TOADDRS),
        SUBJECT,
    )
    msg += f"Use this verification code to activate your account: {verificationCode}"
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.set_debuglevel(1)
    server.ehlo()
    server.starttls()
    server.login(LOGIN, PASSWORD)
    server.sendmail(SENDER, TOADDRS, msg)
    server.quit()

    user = User.get_user_by_email(data)
    if user:
        session["user_id"] = user["id"]
        return redirect("/verify/email")
    else:
        flash("User not found", "userNotFound")
        return redirect(request.referrer)


# Verify Email Route
@app.route("/verify/email")
def verifyEmail():
    if "user_id" not in session:
        return redirect("/")
    data = {"user_id": session["user_id"]}
    user = User.get_user_by_id(data)
    if user["isVerified"] == 1:
        return redirect("/dashboard")
    return render_template("verifyEmail.html", loggedUser=user)


# Email Validation
@app.route("/activate/account", methods=["POST"])
def activateAccount():
    if "user_id" not in session:
        return redirect("/")
    data = {"user_id": session["user_id"]}
    user = User.get_user_by_id(data)
    if user["isVerified"] == 1:
        return redirect("/dashboard")

    if not request.form["verificationCode"]:
        flash("Verification Code is required", "wrongCode")
        return redirect(request.referrer)

    if request.form["verificationCode"] != user["verificationCode"]:
        string = "0123456789"
        vCode = ""
        length = len(string)
        for i in range(8):
            vCode += string[math.floor(random.random() * length)]
        verificationCode = vCode
        dataUpdate = {
            "verificationCode": verificationCode,
            "user_id": session["user_id"],
        }
        User.updateVerificationCode(dataUpdate)
        LOGIN = ADMINEMAIL
        TOADDRS = user["email"]
        SENDER = ADMINEMAIL
        SUBJECT = "Verify Your Email"
        msg = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (
            (SENDER),
            "".join(TOADDRS),
            SUBJECT,
        )
        msg += (
            f"Use this verification code to activate your account: {verificationCode}"
        )
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.set_debuglevel(1)
        server.ehlo()
        server.starttls()
        server.login(LOGIN, PASSWORD)
        server.sendmail(SENDER, TOADDRS, msg)
        server.quit()

        flash("Verification Code is wrong. We just sent you a new one", "wrongCode")
        return redirect(request.referrer)

    User.activateAccount(data)
    return redirect("/dashboard")


# Log In Route
@app.route("/loginPage")
def loginPage():
    if "user_id" in session:
        return redirect("/")
    return render_template("login.html")


# Control Log In Form
@app.route("/login", methods=["POST"])
def login():
    if "user_id" in session:
        return redirect("/")
    if not User.get_user_by_email(request.form):
        flash(
            "This email doesnt appear to be in our system! Try another one!",
            "emailLogin",
        )
        return redirect(request.referrer)

    user = User.get_user_by_email(request.form)
    if user:
        if not bcrypt.check_password_hash(user["password"], request.form["password"]):
            flash("Wrong Password", "passwordLogin")
            return redirect(request.referrer)

    session["user_id"] = user["id"]

    return redirect("/verify/email")


# Edit Post Form Route
@app.route("/edit/profile")
def edit_profile():
    if "user_id" in session:
        data = {
            "user_id": session["user_id"],
        }
        loggedUser = User.get_user_by_id(data)
        if loggedUser["isVerified"] == 0:
            return redirect("/verify/email")
        return render_template("editProfile.html", loggedUser=loggedUser)
    return redirect("/profile")


# Update Profile Form
@app.route("/editProfile", methods=["POST"])
def editProfile():
    if "user_id" in session:
        if not User.validate_user_profile(request.form):
            flash("You have some errors!")
            return redirect(request.referrer)
        data = {
            "user_id": session["user_id"],
            "first_name": request.form["first_name"],
            "last_name": request.form["last_name"],
        }
        loggedUser = User.get_user_by_id(data)
        if loggedUser["isVerified"] == 0:
            return redirect("/verify/email")
        User.update(data)
        return redirect(request.referrer)
    return redirect(request.referrer)


# Dashboard Route
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    data = {"user_id": session["user_id"]}
    loggedUser = User.get_user_by_id(data)
    if loggedUser["isVerified"] == 0:
        return redirect("/verify/email")
    url = "https://api.themoviedb.org/3/movie/popular?language=en-US&page=1&sort_by=popularity.desc"

    headers = {
        "accept": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI5YTk0Y2QzNmM1ZDlhYmNlOGE2OTc1ZTQ1NzA4M2U0NSIsInN1YiI6IjY1MzdiZWVkZjQ5NWVlMDBmZjY1YmFjMSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.uuPeImHHYdXO-uOU0SvkHLZlQrUVxqwiiuoxvu2lRXo",
    }
    response = requests.get(url, headers=headers)
    print(response.json())
    return render_template(
        "index.html",
        loggedUser=loggedUser,
        movies=response.json()['results']
    )


# View Logged User Profile
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/")

    data = {"user_id": session["user_id"]}
    loggedUser = User.get_user_by_id(data)
    if loggedUser["isVerified"] == 0:
        return redirect("/verify/email")
    return render_template(
        "profile.html",
    )
