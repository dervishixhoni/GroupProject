from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash, request
import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")


class User:
    db_name = "movies_db"

    def __init__(self, data):
        self.id = data["id"]
        self.first_name = data["first_name"]
        self.last_name = data["last_name"]
        self.email = data["email"]
        self.password = data["password"]
        self.admin = data["admin"]
        self.verificationCode = data["verificationCode"]
        self.isVerified = data["isVerified"]
        self.created_at = data["created_at"]
        self.updated_at = data["updated_at"]

    # CREATE User
    @classmethod
    def save(cls, data):
        query = (
            "INSERT INTO users (first_name, last_name, email, password, isVerified, "
            "verificationCode, admin) VALUES ( %(first_name)s, %(last_name)s, %(email)s, "
            "%(password)s, %(isVerified)s, %(verificationCode)s, 0);"
        )
        return connectToMySQL(cls.db_name).query_db(query, data)

    # Get User By ID
    @classmethod
    def get_user_by_id(cls, data):
        query = "SELECT * FROM users WHERE users.id = %(user_id)s;"
        results = connectToMySQL(cls.db_name).query_db(query, data)
        if results:
            return results[0]
        return False

    # Get User By Email
    @classmethod
    def get_user_by_email(cls, data):
        query = "SELECT * FROM users WHERE users.email = %(email)s;"
        results = connectToMySQL(cls.db_name).query_db(query, data)
        if results:
            return results[0]
        return False

    # Insert Verification Code
    @classmethod
    def updateVerificationCode(cls, data):
        query = "UPDATE users SET  verificationCode = %(verificationCode)s WHERE users.id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    # Activate Account
    @classmethod
    def activateAccount(cls, data):
        query = "UPDATE users set isVerified = 1 WHERE users.id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    # Update User
    @classmethod
    def update(cls, data):
        query = (
            "UPDATE users SET first_name = %(first_name)s, last_name = %(last_name)s, email = %(email)s WHERE "
            "users.id = %(user_id)s;"
        )
        return connectToMySQL(cls.db_name).query_db(query, data)

    # DELETE User
    @classmethod
    def delete(cls, data):
        query = "DELETE FROM users WHERE users.id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)

    @staticmethod
    def validate_user(user):
        is_valid = True

        if len(user["first_name"]) < 2:
            flash("First name should be more than 2 characters!", "firstNameRegister")
            is_valid = False
        if len(user["last_name"]) < 2:
            flash("Last name should be more than 2 characters!", "lastNameRegister")
            is_valid = False
        if not EMAIL_REGEX.match(user["email"]):
            flash("Invalid email address!", "emailRegister")
            is_valid = False
        if len(user["password"]) < 8:
            flash("Password should be more then 8 characters!", "passwordRegister")
            is_valid = False
        if user["password"] != user["confirmPassword"]:
            flash("Passwords do not match!", "confirmPasswordRegister")
            is_valid = False
        return is_valid

    @staticmethod
    def validate_user_profile(user):
        valid = True

        if len(user["first_name"]) < 2:
            flash("First name should be more than 2 characters!", "firstNameRegister")
            is_valid = False
        if len(user["last_name"]) < 2:
            flash("Last name should be more than 2 characters!", "lastNameRegister")
            is_valid = False
        if not EMAIL_REGEX.match(user["email"]):
            flash("Invalid email address!", "emailRegister")
            is_valid = False
        data = {
            'email' : request.form['email']
        }
        if User.get_user_by_email(data):
            flash('Email already exists','emailexists')
            is_valid = False
        return valid
    
    @classmethod
    def editpassword(cls,data):
        query = "update users set password = %(password)s where id = %(id)s"
        return connectToMySQL(cls.db_name).query_db(query,data)