from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")


class Watchlist:
    db_name = "movies_db"

    def __init__(self, data):
        self.id = data["id"]
        self.title = data["title"]
        self.release_year = data["release_year"]
        self.rating = data["rating"]
        self.user_id = data["user_id"]
        self.movie_id = data["movie_id"]
        self.created_at = data["created_at"]
        self.updated_at = data["updated_at"]
    @classmethod
    def save(cls, data):
        query = "INSERT INTO watchlists (title, release_year, rating, user_id,movie_id) VALUES ( %(title)s, %(release_year)s, %(rating)s, %(user_id)s, %(movie_id)s);"
        return connectToMySQL(cls.db_name).query_db(query, data)
    @classmethod
    def delete(cls, data):
        query = "DELETE FROM watchlists WHERE movie_id = %(movie_id)s and user_id = %(user_id)s;"
        return connectToMySQL(cls.db_name).query_db(query, data)
    @classmethod
    def get_User_Watchlist(cls,data):
        query = "Select * from watchlists where user_id = %(user_id)s"
        results = connectToMySQL(cls.db_name).query_db(query,data)
        listtowatch = []
        if results:
            for item in results:
                listtowatch.append(item)
        return listtowatch
    @classmethod
    def get_User_Watchlist_movie_id(cls,data):
        query = "Select * from watchlists where user_id = %(user_id)s"
        results = connectToMySQL(cls.db_name).query_db(query,data)
        listtowatch = []
        if results:
            for item in results:
                listtowatch.append(item['movie_id'])
        return listtowatch