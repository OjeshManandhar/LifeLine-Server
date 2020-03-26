from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
# password lai hash garna
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import jwt  # token ko lai
import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from flask import send_file


# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'buzzgopa'
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socket = SocketIO(app)
# Init driver_db
driver_db = SQLAlchemy(app)

# Init ma
driver_ma = Marshmallow(app)

# Init traffic_db
traffic_db = SQLAlchemy(app)

# Init traffic_ma
traffic_ma = Marshmallow(app)


# Driver Class/Model
class Driver(driver_db.Model):
    did = driver_db.Column(driver_db.Integer, primary_key=True)
    name = driver_db.Column(driver_db.String(200), unique=True)
    driver_id = driver_db.Column(driver_db.String(200), unique=True)
    email = driver_db.Column(driver_db.String(200), unique=True)
    contact = driver_db.Column(driver_db.Integer, unique=True)
    password = driver_db.Column(driver_db.String(200))
    pic_location = driver_db.Column(driver_db.String(200))

    def __init__(self, name, driver_id, email, contact, password):
        self.name = name
        self.driver_id = driver_id
        self.email = email
        self.contact = contact
        self.password = password

    def put_pic_loc(self, pic_location):
        self.pic_location = pic_location

    def update_data(self, name, driver_id, email, contact):
        self.name = name
        self.driver_id = driver_id
        self.email = email
        self.contact = contact


# Driver Schema
class DriverSchema(driver_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'driver_id', 'email',
                  'contact', 'password', 'pic_location')


# Traffic Class/Model
class Traffic(traffic_db.Model):
    tid = traffic_db.Column(traffic_db.Integer, primary_key=True)
    name = traffic_db.Column(traffic_db.String(100), unique=True)
    email = traffic_db.Column(traffic_db.String(200), unique=True)
    contact = traffic_db.Column(traffic_db.Integer, unique=True)
    password = traffic_db.Column(traffic_db.String(200))
    pic_location = traffic_db.Column(traffic_db.String(200))

    def __init__(self, name, email, contact, password):
        self.name = name
        self.email = email
        self.contact = contact
        self.password = password

    def put_pic_loc(self, pic_location):
        self.pic_location = pic_location

    def update_data(self, name, email, contact):
        self.name = name
        self.email = email
        self.contact = contact


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
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# Init schema
driver_schema = DriverSchema()
drivers_schema = DriverSchema(many=True)

# Sign up
@app.route('/driver_signup', methods=['POST'])
def Sign_up_driver():

    name = request.json['name']
    driver_id = request.json['driver_id']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']
    pic_location = os.path.join(basedir, 'User_pics/driver', name)

    hashed_password = generate_password_hash(password, method='sha256')

    new_driver = Driver(name, driver_id, email, contact, hashed_password)

    driver_db.session.add(new_driver)
    driver_db.session.commit()

    return driver_schema.jsonify(new_driver)


@app.route('/update_driver_pic/<contact>', methods=['POST'])
def update_driver_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    # check if the post request has the file part
    if 'file' not in request.files:
        response = jsonify({'message': 'No file part in the request'})
        response.status_code = 400
        return response
    file = request.files['file']
    if file.filename == '':
        response = jsonify({'message': 'No file selected for uploading'})
        response.status_code = 400
        return response
    if file.filename[-4:] != '.png' and file.filename[-4:] != '.jpg':
        response = jsonify({'message': 'png or jpg not selected'})
        response.status_code = 400
        return response

    pic_loc = os.path.join(basedir, "User_pics/driver",
                           (str(driver.contact)+file.filename[-4:]))
    file.save(pic_loc)
    driver.put_pic_loc(pic_loc)
    response = jsonify({'message': 'File successfully uploaded'})
    driver_db.session.commit()
    return response

# Get Drivers
@app.route('/driver', methods=['GET'])
def get_drivers():
    all_drivers = Driver.query.all()
    result = drivers_schema.dump(all_drivers)  # array vayeko le
    return jsonify(result)

# Get Drivers pic
@app.route('/get_driver_pic/<contact>', methods=['GET'])
def get_driver_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    return send_file(driver.pic_location)

# Get single drivers
@app.route('/driver/<contact>', methods=['GET'])
def get_driver(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    return driver_schema.jsonify(driver)

# Update a Driver
@app.route('/driver/<contact>', methods=['PUT'])
def update_driver(contact):
    driver = Driver.query.filter_by(contact=contact).first()

    if not driver:
        return jsonify({'message': 'no driver found'})
    print(driver.contact, request.json['contact'])
    if driver.contact != request.json['contact']:
        pic_loc = os.path.join(basedir, "User_pics/driver",
                           (str(request.json['contact'])+driver.pic_location[-4:]))
        os.rename(driver.pic_location,pic_loc)
        driver.put_pic_loc(pic_loc)
    driver.update_data(request.json['name'], request.json['driver_id'], request.json['email'], request.json['contact'])
    driver_db.session.commit()

    return driver_schema.jsonify(driver)

# Delete drivers
@app.route('/driver/<contact>', methods=['DELETE'])
def delete_driver(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    os.remove(driver.pic_location)
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

    driver = Driver.query.filter_by(name=auth.username).first()

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

    hashed_password = generate_password_hash(password, method='sha256')

    new_traffic = Traffic(name, email, contact, hashed_password)
    traffic_db.session.add(new_traffic)
    traffic_db.session.commit()
    return traffic_schema.jsonify(new_traffic)


@app.route('/update_traffic_pic/<contact>', methods=['POST'])
def update_traffic_pic(contact):
    # check if the post request has the file part\
    traffic = Traffic.query.filter_by(contact=contact).first()
    # check if the post request has the file part
    if 'file' not in request.files:
        response = jsonify({'message': 'No file part in the request'})
        response.status_code = 400
        return response
    file = request.files['file']
    if file.filename == '':
        response = jsonify({'message': 'No file selected for uploading'})
        response.status_code = 400
        return response
    if file.filename[-4:] != '.png' and file.filename[-4:] != '.jpg':
        response = jsonify({'message': 'png or jpg not selected'})
        response.status_code = 400
        return response

    pic_loc = os.path.join(basedir, "User_pics/traffic",
                           (str(traffic.contact)+file.filename[-4:]))
    file.save(pic_loc)
    traffic.put_pic_loc(pic_loc)
    response = jsonify({'message': 'File successfully uploaded'})
    traffic_db.session.commit()
    return response

# Get Traffics
@app.route('/traffic', methods=['GET'])
def get_traffics():
    all_traffics = Traffic.query.all()
    result = traffics_schema.dump(all_traffics)  # array vayeko le
    return jsonify(result)

# Get Traffic pic
@app.route('/get_traffic_pic/<contact>', methods=['GET'])
def get_traffic_pic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    return send_file(traffic.pic_location)

# Get single traffics
@app.route('/traffic/<contact>', methods=['GET'])
def get_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    return traffic_schema.jsonify(traffic)

# Update a Traffic
@app.route('/traffic/<contact>', methods=['PUT'])
def update_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()

    if not traffic:
        return jsonify({'message': 'no traffic found'})

    if traffic.contact != request.json['contact']:
        pic_loc = os.path.join(basedir, "User_pics/traffic",
                           (str(request.json['contact'])+traffic.pic_location[-4:]))
        os.rename(traffic.pic_location,pic_loc)
        traffic.put_pic_loc(pic_loc)
    traffic.update_data(request.json['name'], request.json['email'], request.json['contact'])
    traffic_db.session.commit()

    return traffic_schema.jsonify(traffic)


# Delete traffics
@app.route('/traffic/<contact>', methods=['DELETE'])
def delete_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    if not traffic:
        return jsonify({'message': 'no traffic found'})
    os.remove(traffic.pic_location)
    traffic_db.session.delete(traffic)
    traffic_db.session.commit()
    return traffic_schema.jsonify(traffic)

# login TrafficSchema http basic auth
@app.route('/traffic_login', methods=['POST'])
def login_traffic():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    traffic = Traffic.query.filter_by(name=auth.username).first()

    if not traffic:
        return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(traffic.password, auth.password):
        token = jwt.encode({'id': traffic.tid}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify3', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

# Test section
@app.route('/file_upload', methods=['POST'])
def upload_file():
    # check if the post request has the file part
    # check if the post request has the file part
    if 'file' not in request.files:
        response = jsonify({'message': 'No file part in the request'})
        response.status_code = 400
        return response
    file = request.files['file']

    if file.filename == '':
        response = jsonify({'message': 'No file selected for uploading'})
        response.status_code = 400
        return response

    filename = secure_filename(file.filename)
    file.save(os.path.join(basedir, filename))
    response = jsonify({'message': 'File successfully uploaded'})
    response.status_code = 201
    return response


@app.route('/get_image')
def get_image():
    return send_file(os.path.join(basedir, "pic.png"))


# Runserver
if __name__ == "__main__":
    socket.run(app, debug=True)
    # app.run(debug=True)
