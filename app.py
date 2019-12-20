from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
from werkzeug.security import generate_password_hash, check_password_hash #password lai hash garna
from flask_socketio import SocketIO, emit
import jwt # token ko lai
import datetime
from functools import wraps 




# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'buzzgopa'
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socket = SocketIO(app)
# Init db
db = SQLAlchemy(app)
# Init ma
ma = Marshmallow(app)

# User Class/Model


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    driver_id = db.Column(db.String(200), unique = True)
    email = db.Column(db.String(200))
    contact = db.Column(db.Integer, unique = True)
    password = db.Column(db.String(200))
    job = db.Column(db.String(200))


    def __init__(self, name, driver_id, email, contact, password, job):
        self.name = name
        self.driver_id = driver_id
        self.email = email
        self.contact = contact
        self.password = password
        self.job = job
        

# User Schema


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'driver_id', 'email', 'contact', 'password', 'job')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Init schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Sign up
@app.route('/signup', methods=['POST'])
def Sign_up():
    name = request.json['name']
    driver_id = request.json[ 'driver_id']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']
    job = request.json['job']

    hashed_password = generate_password_hash(password, method = 'sha256')

    new_user = User(name, driver_id, email, contact, hashed_password, job)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)

# Get Users
@app.route('/user', methods=['GET'])
def get_users():
    all_users = User.query.all()    
    result = users_schema.dump(all_users) #array vayeko le
    return jsonify(result)

# Get single users 
@app.route('/user/<id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    return user_schema.jsonify(user)

# Update a User
@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)

    if not user:
        return jsonify({'message': 'no user found'})


    name = request.json['name']
    driver_id = request.json['driver_id']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']
    job = request.json['job']

    user.name = name
    user.driver_id = driver_id
    user.email = email
    user.contact = contact
    user.password = password
    user.job = job
    new_user = User(name, driver_id, email, contect, password, job)

    db.session.commit()

    return user_schema.jsonify(user)

# Delete users 
@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'no user found'})
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)

# login users http basic auth 
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    user = User.query.filter_by(name = auth.username).first()

    if not user:
        return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id': user.id}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify3', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

# Runserver
if __name__ == "__main__":
    socket.run(app, debug = True)
    #app.run(debug=True)
