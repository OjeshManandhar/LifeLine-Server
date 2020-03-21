from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
from werkzeug.security import generate_password_hash, check_password_hash #password lai hash garna
from flask_socketio import SocketIO, emit
import jwt # token ko lai
import datetime
from functools import wraps 
from werkzeug.utils import secure_filename



# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'buzzgopa'
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socket = SocketIO(app)
# Init driver_db
driver_db = SQLAlchemy(app)

# Init ma
driver_ma = Marshmallow(app)

#Init traffic_db
traffic_db = SQLAlchemy(app)

# Init traffic_ma
traffic_ma = Marshmallow(app)


# Driver Class/Model
class Driver(driver_db.Model):
    did = driver_db.Column(driver_db.Integer, primary_key=True)
    driver_id = driver_db.Column(driver_db.String(200), unique = True)
    email = driver_db.Column(driver_db.String(200))
    contact = driver_db.Column(driver_db.Integer, unique = True)
    password = driver_db.Column(driver_db.String(200))
    pic_location = driver_db.Column(driver_db.String(200))


    def __init__(self, name, driver_id, email, contact, password, pic_location):
        self.name = name
        self.driver_id = driver_id
        self.email = email
        self.contact = contact
        self.password = password
        self.pic_location = pic_location
        

# Driver Schema
class DriverSchema(driver_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'driver_id', 'email', 'contact', 'password', 'pic_location')


# Traffic Class/Model
class Traffic(traffic_db.Model):
    tid = traffic_db.Column(traffic_db.Integer, primary_key=True)
    name = traffic_db.Column(traffic_db.String(100), unique=True)
    email = traffic_db.Column(traffic_db.String(200))
    contact = traffic_db.Column(traffic_db.Integer, unique = True)
    password = traffic_db.Column(traffic_db.String(200))
    pic_location = driver_db.Column(driver_db.String(200))
    

    def __init__(self, name, email, contact, password, pic_location):
        self.name = name
        self.email = email
        self.contact = contact
        self.password = password
        self.pic_location = pic_location



# Traffic Schema
class TrafficSchema(traffic_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'email', 'contact', 'password', 'pic_location')

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
driver_schema = DriverSchema()
drivers_schema = DriverSchema(many=True)

# Sign up
@app.route('/driver_signup', methods=['POST'])
def Sign_up_driver():

    name = request.json['name']
    driver_id = request.json[ 'driver_id']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']

    if 'file' not in request.files:
        response = jsonify({'message' : 'No file part in the request'})
        response.status_code = 400
        return response
    file = request.files['file']
    if file.filename == '':
        response = jsonify({'message' : 'No file selected for uploading'})
        response.status_code = 400
        return response
    
    pic_location = os.path.join(basedir, 'User_pics/driver', name)
    file.save(pic_location)
    

    hashed_password = generate_password_hash(password, method = 'sha256')

    new_driver = Driver(name, driver_id, email, contact, hashed_password, pic_location)

    driver_db.session.add(new_driver)
    driver_db.session.commit()

    return driver_schema.jsonify(new_driver)

# Get Drivers
@app.route('/driver', methods=['GET'])
def get_drivers():
    all_drivers = Driver.query.all()    
    result = drivers_schema.dump(all_drivers) #array vayeko le
    return jsonify(result)

# Get single drivers 
@app.route('/driver/<id>', methods=['GET'])
def get_driver(id):
    driver = Driver.query.get(id)
    return driver_schema.jsonify(driver)

# Update a Driver
@app.route('/driver/<id>', methods=['PUT'])
def update_driver(id):
    driver = Driver.query.get(id)

    if not driver:
        return jsonify({'message': 'no driver found'})


    name = request.json['name']
    driver_id = request.json['driver_id']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']

    driver.name = name
    driver.driver_id = driver_id
    driver.email = email
    driver.contact = contact
    driver.password = password
    new_driver = Driver(name, driver_id, email, contect, password)

    driver_db.session.commit()

    return driver_schema.jsonify(driver)

# Delete drivers 
@app.route('/driver/<id>', methods=['DELETE'])
def delete_driver(id):
    driver = Driver.query.get(id)
    if not driver:
        return jsonify({'message': 'no driver found'})
    driver_db.session.delete(driver)
    driver_db.session.commit()
    return driver_schema.jsonify(driver)

# login DriverSchema http basic auth 
@app.route('/driver_login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    driver = Driver.query.filter_by(name = auth.username).first()

    if not driver:
        return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(driver.password, auth.password):
        token = jwt.encode({'id': driver.did}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify3', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})





# Init traffic schema
traffic_schema = TrafficSchema()
traffics_schema = TrafficSchema(many=True)

# Traffic Sign up
@app.route('/traffic_signup', methods=['POST'])
def Sign_up_traffic():
    name = request.json['name']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']

    hashed_password = generate_password_hash(password, method = 'sha256')

    if 'file' not in request.files:
        response = jsonify({'message' : 'No file part in the request'})
        response.status_code = 400
        return response
    file = request.files['file']
    if file.filename == '':
        response = jsonify({'message' : 'No file selected for uploading'})
        response.status_code = 400
        return response
    
    pic_location = os.path.join(basedir, 'User_pics/traffic', name)
    file.save(pic_location)
    
    hashed_password = generate_password_hash(password, method = 'sha256')
    
    new_traffic = Traffic(name, email, contact, hashed_password, pic_location)
    traffic_db.session.add(new_traffic)
    traffic_db.session.commit()
    return traffic_schema.jsonify(new_traffic)

# Get Traffics
@app.route('/traffic', methods=['GET'])
def get_traffics():
    all_traffics = Traffic.query.all()    
    result = traffics_schema.dump(all_traffics) #array vayeko le
    return jsonify(result)

# Get single traffics 
@app.route('/traffic/<id>', methods=['GET'])
def get_traffic(id):
    traffic = Traffic.query.get(id)
    return traffic_schema.jsonify(traffic)

# Update a Traffic
@app.route('/traffic/<id>', methods=['PUT'])
def update_traffic(id):
    traffic = Traffic.query.get(id)

    if not traffic:
        return jsonify({'message': 'no traffic found'})


    name = request.json['name']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']

    traffic.name = name
    traffic.email = email
    traffic.contact = contact
    traffic.password = password
    new_traffic = Traffic(name, email, contect, password)

    traffic_db.session.commit()

    return traffic_schema.jsonify(traffic)

# Delete traffics 
@app.route('/traffic/<id>', methods=['DELETE'])
def delete_traffic(id):
    traffic = Traffic.query.get(id)
    if not traffic:
        return jsonify({'message': 'no traffic found'})
    traffic_db.session.delete(traffic)
    traffic_db.session.commit()
    return traffic_schema.jsonify(traffic)

# login TrafficSchema http basic auth 
@app.route('/traffic_login', methods=['POST'])
def login_traffic():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    traffic = Traffic.query.filter_by(name = auth.username).first()

    if not traffic:
        return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(traffic.password, auth.password):
        token = jwt.encode({'id': traffic.tid}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify3', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

@app.route('/file_upload', methods=['POST'])
def upload_file():
    # check if the post request has the file part
    print(request.files)
    # check if the post request has the file part
    if 'file' not in request.files:
        response = jsonify({'message' : 'No file part in the request'})
        response.status_code = 400
        return response
    file = request.files['file']
    print(file)
    if file.filename == '':
        response = jsonify({'message' : 'No file selected for uploading'})
        response.status_code = 400
        return response
    
    filename = secure_filename(file.filename)
    file.save(os.path.join(basedir, filename))
    response = jsonify({'message' : 'File successfully uploaded'})
    response.status_code = 201
    return response


# Runserver
if __name__ == "__main__":  
    socket.run(app, debug = True)
    #app.run(debug=True)