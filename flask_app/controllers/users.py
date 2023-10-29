import datetime
import math
import random
import smtplib
from flask_app import app
from flask_app.models.user import User
from flask_app.models.watchlist import Watchlist
from flask_app.config.mysqlconnection import connectToMySQL
import requests

from flask import render_template, redirect, session, request, flash
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

from .env import ADMINEMAIL
from .env import PASSWORD

genredict = {
    28: "Action",
    12: "Adventure",
    16: "Animation",
    35: "Comedy",
    80: "Crime",
    99: "Documentary",
    18: "Drama",
    10751: "Family",
    14: "Fantasy",
    36: "History",
    27: "Horror",
    10402: "Music",
    9648: "Mystery",
    10749: "Romance",
    878: "Science Fiction",
    10770: "TV Movie",
    53: "Thriller",
    10752: "War",
    37: "Western",
}


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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/registerPage")


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


# Update Profile Form
@app.route("/editprofile", methods=["POST"])
def editProfile():
    if "user_id" in session:
        if not User.validate_user_profile(request.form):
            flash("You have some errors!")
            return redirect(request.referrer)
        data = {
            "user_id": session["user_id"],
            "first_name": request.form["first_name"],
            "last_name": request.form["last_name"],
            "email": request.form["email"],
        }
        loggedUser = User.get_user_by_id(data)
        if loggedUser["isVerified"] == 0:
            return redirect("/verify/email")
        User.update(data)
        return redirect(request.referrer)
    return redirect(request.referrer)


@app.route("/editpassword", methods=["POST"])
def editPassword():
    if "user_id" not in session:
        return redirect("/")
    data = {"user_id": session["user_id"]}
    if not bcrypt.check_password_hash(
        request.form["oldpass"], User.get_user_by_id(data)["password"]
    ):
        flash("Old Password does not match!", "oldpassword")
        return redirect(request.referrer)
    if len(request.form["newpass"]) < 8:
        flash("New Password should be longer than 8 Charachters", "newpassword")
        return redirect(request.referrer)
    if request.form["confimpass"] != request.form["newpass"]:
        flash("Confirm Password should match New Password", "confirmpassword")
        return redirect(request.referrer)
    data = {
        "password": bcrypt.generate_password_hash(request.form["newpass"]),
        "id": session["user_id"],
    }
    User.editpassword(data)
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
    todayurl = "https://api.themoviedb.org/3/trending/movie/day?language=en-US"
    thisweekurl = "https://api.themoviedb.org/3/trending/movie/week?language=en-US"
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI5YTk0Y2QzNmM1ZDlhYmNlOGE2OTc1ZTQ1NzA4M2U0NSIsInN1YiI6IjY1MzdiZWVkZjQ5NWVlMDBmZjY1YmFjMSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.uuPeImHHYdXO-uOU0SvkHLZlQrUVxqwiiuoxvu2lRXo",
    }
    response = requests.get(url, headers=headers)
    todayresponse = requests.get(todayurl, headers=headers)
    thisweekresponse = requests.get(thisweekurl, headers=headers)
    return render_template(
        "index.html",
        loggedUser=loggedUser,
        movies=response.json()["results"],
        genredict=genredict,
        todaytrending=todayresponse.json()["results"][:18],
        thisweektrending=thisweekresponse.json()["results"][:18],
    )


@app.route("/details/<int:id>")
def details(id):
    if "user_id" not in session:
        return redirect("/")
    data = {"user_id": session["user_id"]}
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI5YTk0Y2QzNmM1ZDlhYmNlOGE2OTc1ZTQ1NzA4M2U0NSIsInN1YiI6IjY1MzdiZWVkZjQ5NWVlMDBmZjY1YmFjMSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.uuPeImHHYdXO-uOU0SvkHLZlQrUVxqwiiuoxvu2lRXo",
    }
    detailurl = f"https://api.themoviedb.org/3/movie/{id}?language=en-US"
    response = requests.get(detailurl, headers=headers)
    videourl = f"https://api.themoviedb.org/3/movie/{id}/videos?language=en-US"
    videoresponse = requests.get(videourl, headers=headers)
    trailer_url = "notrailer"
    if videoresponse != 200:
        for r in videoresponse.json()["results"]:
            if r["type"] == "Trailer" and r["site"] == "YouTube":
                trailer_url = r["key"]
    genres = ""
    for i in range(len(response.json()["genres"]) - 1):
        genres += str(response.json()["genres"][i]["id"]) + "|"
    genres += str(response.json()["genres"][len(response.json()["genres"]) - 1]["id"])
    url = f"https://api.themoviedb.org/3/discover/movie?include_adult=false&language=en-US&page=1&sort_by=popularity.desc&with_genres={genres}"
    recresponse = requests.get(url, headers=headers)
    return render_template(
        "details.html",
        movie=response.json(),
        recommendations=recresponse.json(),
        trailer=trailer_url,
        genredict=genredict,
        watchlist=Watchlist.get_User_Watchlist_movie_id(data),
        loggedUser=User.get_user_by_id({"user_id": session["user_id"]}),
    )


@app.route("/catalog")
def catalog():
    if "user_id" not in session:
        return redirect("/")
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI5YTk0Y2QzNmM1ZDlhYmNlOGE2OTc1ZTQ1NzA4M2U0NSIsInN1YiI6IjY1MzdiZWVkZjQ5NWVlMDBmZjY1YmFjMSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.uuPeImHHYdXO-uOU0SvkHLZlQrUVxqwiiuoxvu2lRXo",
    }
    url = "https://api.themoviedb.org/3/movie/popular?language=en-US&page=1&sort_by=popularity.desc"
    response = requests.get(url, headers=headers)
    return render_template(
        "catalog.html",
        base=response.json()["results"][:18],
        genredict=genredict,
        loggedUser=User.get_user_by_id({"user_id": session["user_id"]}),
    )


@app.route("/catalog/<int:id>")
def catalogwithgenre(id):
    if "user_id" not in session:
        return redirect("/")
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI5YTk0Y2QzNmM1ZDlhYmNlOGE2OTc1ZTQ1NzA4M2U0NSIsInN1YiI6IjY1MzdiZWVkZjQ5NWVlMDBmZjY1YmFjMSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.uuPeImHHYdXO-uOU0SvkHLZlQrUVxqwiiuoxvu2lRXo",
    }
    url = f"https://api.themoviedb.org/3/discover/movie?include_adult=false&include_video=false&language=en-US&page=1&sort_by=popularity.desc&with_genres={id}"
    response = requests.get(url, headers=headers)
    return render_template(
        "catalog.html",
        base=response.json()["results"][:18],
        genredict=genredict,
        loggedUser=User.get_user_by_id({"user_id": session["user_id"]}),
        preset = genredict[id]  
    )


@app.route("/search", methods=["POST"])
def search():
    if "user_id" not in session:
        return redirect("/")
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI5YTk0Y2QzNmM1ZDlhYmNlOGE2OTc1ZTQ1NzA4M2U0NSIsInN1YiI6IjY1MzdiZWVkZjQ5NWVlMDBmZjY1YmFjMSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.uuPeImHHYdXO-uOU0SvkHLZlQrUVxqwiiuoxvu2lRXo",
    }

    search = request.form["keyword"]

    url = f"https://api.themoviedb.org/3/search/movie?query={search}&include_adult=false&language=en-US&page=1"

    response = requests.get(url, headers=headers)

    data = response.json()
    results = data.get("results", [])

    if response.status_code == 200:
        print(results)
        return render_template(
            "result.html",
            movies=results,
            genredict=genredict,
            loggedUser=User.get_user_by_id({"user_id": session["user_id"]}),
        )
    else:
        return redirect(request.referrer)


@app.route("/profile/<int:id>")
def profile(id):
    if "user_id" not in session and session["user_id"] != id:
        return redirect("/")
    data = {"user_id": session["user_id"]}
    loggedUser = User.get_user_by_id(data)
    print(Watchlist.get_User_Watchlist(data))
    print(Watchlist.get_User_Watchlist_movie_id(data))
    if loggedUser["isVerified"] == 0:
        return redirect("/verify/email")
    return render_template(
        "profile.html",
        loggedUser=loggedUser,
        watchlist=Watchlist.get_User_Watchlist(data),
    )


@app.route("/watch/<int:id>", methods=["POST"])
def watchlist(id):
    if "user_id" not in session:
        return redirect("/")
    data = {
        "user_id": session["user_id"],
        "movie_id": id,
        "title": request.form["title"],
        "release_year": request.form["release_year"],
        "rating": request.form["rating"],
    }
    loggedUser = User.get_user_by_id(data)
    Watchlist.save(data)
    return redirect(request.referrer)


@app.route("/remove/<int:id>")
def remove(id):
    if "user_id" not in session:
        return redirect("/")
    data = {
        "user_id": session["user_id"],
        "movie_id": id,
    }
    loggedUser = User.get_user_by_id(data)
    Watchlist.delete(data)
    return redirect(request.referrer)
