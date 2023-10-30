from flask_app import app
from flask_app.controllers import users

#import controllers

if __name__== '__main__':
    app.run(debug=True,host ="192.168.1.76")