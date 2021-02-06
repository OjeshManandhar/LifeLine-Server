from flask import Flask, request, jsonify, make_response
from LifeLineServer import *
import os
from flask import send_file
import datetime
from werkzeug.utils import secure_filename

from PIL import Image
from io import BytesIO
import base64


# password lai hash garna
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # token ko lai
from functools import wraps

from LifeLineServer.models import Driver, DriverSchema



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print(data)
            current_user = Driver.query.filter_by(tid = data['id']).first()
            users = Driver.query.all()       
            for user in users:
                user_data = {}
                user_data['id'] = user.tid
                if user.tid == current_user.tid and data['role'] == "driver":
                    actual_user = current_user
        except:
            return jsonify({'message' : 'Invalid token'}), 401
        return f(actual_user, *args, **kwargs)
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


@app.route('/driver_pic/<contact>', methods=['POST'])
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
    
    try:
        os.remove(driver.pic_location)
    except:
        print("new pic")

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
@app.route('/driver_pic/<contact>', methods=['GET'])
#@token_required

def get_driver_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    return send_file(driver.pic_location)

# Get driver small pic
@app.route('/driver_small_pic/<contact>', methods=['GET'])
def get_driver_small_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    image = Image.open(driver.pic_location)
    new_image = image.resize((100, 100))
    buff = BytesIO()
    new_image.save(buff, format="JPEG")
    img_str = base64.b64encode(buff.getvalue())
    print(type(img_str))
    return b'data:image/jpg;base64,'+img_str


# Get single drivers
@app.route('/driver/<contact>', methods=['GET'])
#@token_required
def get_driver(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    return driver_schema.jsonify(driver)

# Update a Driver
@app.route('/driver/<contact>', methods=['PUT'])
#@token_required
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
#@token_required
def delete_driver(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    try:
        os.remove(driver.pic_location)
    except:
        print("no_pic-")
    if not driver:
        return jsonify({'message': 'no driver found'})
    driver_db.session.delete(driver)
    driver_db.session.commit()
    return driver_schema.jsonify(driver)

# login DriverSchema http basic auth
@app.route('/driver_login', methods=['POST'])
def login():
    auth = request.authorization
    print(request)

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    driver = Driver.query.filter_by(contact=auth.username).first()

    if not driver:
        return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(driver.password, auth.password):
        token = jwt.encode({'id': driver.contact, 'role': "driver"}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8'), 'contact': driver.contact, 'name': driver.name, 'role': 'Driver'})

    return make_response('Could not verify3', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})