from flask import Flask, request, jsonify, make_response
from LifeLineServer import *
import os
from flask import send_file
import datetime
from werkzeug.utils import secure_filename

from PIL import Image
from io import BytesIO
import base64
import re 


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
            return jsonify({'err' : 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print(data)
            current_user = Driver.query.filter_by(contact = data['id']).first()
            users = Driver.query.all()       
            for user in users:
                user_data = {}
                user_data['id'] = user.contact
                if user.contact == current_user.contact and data['role'] == "driver":
                    actual_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'err' : 'Signature expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'err' : 'Invalid token'}), 401
        return f(actual_user, *args, **kwargs)
    return decorated


# Init schema
driver_schema = DriverSchema()
drivers_schema = DriverSchema(many=True)

# token auth
@app.route('/driver_check_token', methods=['GET'])
@token_required
def driver_check_token(user):
    if user:
        token = jwt.encode(
            {'id': user.contact, 'role': "driver", 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=2)}, 
            app.config['SECRET_KEY'], 
        )
        return jsonify({'new_token': token.decode('UTF-8')})
    else:
        return jsonify({'err' : 'Invalid token'}), 401

# login DriverSchema http basic auth
@app.route('/driver_login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Login credentials missing', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})
    driver = Driver.query.filter_by(contact=auth.username).first()
    if not driver:
        return make_response('Phone number is not registered yet', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})
    if check_password_hash(driver.password, auth.password):
        token = jwt.encode(
            {'id': driver.contact, 'role': "driver", 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=2)}, 
            app.config['SECRET_KEY'], 
        )
        return jsonify({'token': token.decode('UTF-8'), 'contact': driver.contact, 'name': driver.name, 'role': 'driver'})

    return make_response('Phone number and Password does not match', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})


# Sign up
@app.route('/driver_signup', methods=['POST'])
def Sign_up_driver():

    name = request.json['name']
    driver_id = request.json['driver_id']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']
    email_regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if(re.search(email_regex,email) and len(str(contact)) == 10 and len(password)>7): 
        hashed_password = generate_password_hash(password, method='sha256:100')
        new_driver = Driver(name, driver_id, email, contact, hashed_password)
        driver_db.session.add(new_driver)
        try:
            driver_db.session.commit()
        except exc.SQLAlchemyError as e:
            return jsonify({'message': str(e.__dict__['orig'])})
        return driver_schema.jsonify(new_driver)
    else:
        return jsonify({'err': 'Signup Unsuccessful invalid data'}), 401



@app.route('/driver_pic/<contact>', methods=['POST'])
def update_driver_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    # check if the post request has the file part
    if 'file' not in request.files:
        response = jsonify({'err': 'No file part in the request'})
        return response , 400
    file = request.files['file']
    if file.filename == '':
        response = jsonify({'err': 'No file selected for uploading'})
        return response , 400
    if file.filename[-4:] != '.png' and file.filename[-4:] != '.jpg':
        response = jsonify({'err': 'png or jpg not selected'})
        return response , 400

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
    contact = request.args.get('contact')
    name = request.args.get('name')
    final_result = []
    if (contact or name):
        for user in result:
            if name:
                if name in user['name']:
                    final_result.append(user)
            if contact:
                if str(contact) in str(user['contact']):
                    final_result.append(user)
    else:
        final_result = result
    return jsonify(final_result)

# Get Drivers pic
@app.route('/driver_pic/<contact>', methods=['GET'])
#@token_required

def get_driver_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    if driver.pic_location:
        return send_file(driver.pic_location)
    else:
        return jsonify({'err': 'Image not found'}), 404

# Get driver small pic
@app.route('/driver_small_pic/<contact>', methods=['GET'])
def get_driver_small_pic(contact):
    driver = Driver.query.filter_by(contact=contact).first()
    if (not (driver.pic_location)):
        return jsonify({'err': 'Image not found'}), 404
    image = Image.open(driver.pic_location)
    new_image = image.resize((100, 100))
    buff = BytesIO()
    new_image.save(buff, format="JPEG")
    img_str = base64.b64encode(buff.getvalue())
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
        return jsonify({'err': 'no driver found'}), 404
    if driver.contact != request.json['contact']:
        pic_loc = os.path.join(basedir, "User_pics/driver",
                           (str(request.json['contact'])+driver.pic_location[-4:]))
        os.rename(driver.pic_location,pic_loc)
        driver.put_pic_loc(pic_loc)
    driver.update_data(request.json['name'], request.json['driver_id'], request.json['email'], request.json['contact'])
    driver_db.session.commit()

    return driver_schema.jsonify(driver)

# Update a Driver password
@app.route('/driver_password/<contact>', methods=['PUT'])
#@token_required
def update_driver_password(contact):
    driver = Driver.query.filter_by(contact=contact).first()

    if not driver:
        response = jsonify({'err': 'no driver found'})
        return response, 404

    if driver.contact != request.json['contact']:
        pic_loc = os.path.join(basedir, "User_pics/driver",
                           (str(request.json['contact'])+driver.pic_location[-4:]))
        os.rename(driver.pic_location,pic_loc)
        driver.put_pic_loc(pic_loc)

    password = hashed_password = generate_password_hash(request.json['password'], method='sha256:100')
    driver.update_password(password)
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
        return jsonify({'err': 'no driver found'}), 404
    driver_db.session.delete(driver)
    driver_db.session.commit()
    return driver_schema.jsonify(driver)
