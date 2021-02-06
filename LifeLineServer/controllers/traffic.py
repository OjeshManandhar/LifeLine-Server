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

from LifeLineServer.models import Driver, Traffic, DriverSchema, TrafficSchema

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
            current_user = Traffic.query.filter_by(tid = data['id']).first()
            users = Traffic.query.all()       
            for user in users:
                user_data = {}
                user_data['id'] = user.tid
                if user.tid == current_user.tid and data['role'] == "traffic":
                    actual_user = current_user
        except:
            return jsonify({'message' : 'Invalid token'}), 401
        return f(actual_user, *args, **kwargs)
    return decorated



# Get single traffics
@app.route('/traffic/<contact>', methods=['GET'])
# @token_required
def get_traffic(actual_user, contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    return traffic_schema.jsonify(traffic)

# Update a Traffic
@app.route('/traffic/<contact>', methods=['PUT'])
#@token_required
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


@app.route('/traffic_pic/<contact>', methods=['POST'])
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

    try:
        os.remove(traffic.pic_location)
    except:
        print("new pic")

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

# Get Traffic small pic
@app.route('/traffic_small_pic/<contact>', methods=['GET'])
def traffic_small_pic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    image = Image.open(traffic.pic_location)
    new_image = image.resize((100, 100))
    buff = BytesIO()
    new_image.save(buff, format="JPEG")
    img_str = base64.b64encode(buff.getvalue())
    return b'data:image/jpg;base64,'+img_str

# Delete traffics
@app.route('/traffic/<contact>', methods=['DELETE'])
def delete_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    if not traffic:
        return jsonify({'message': 'no traffic found'})
    try:
        os.remove(traffic.pic_location)
    except:
        print("no_pic-")
    traffic_db.session.delete(traffic)
    traffic_db.session.commit()
    return traffic_schema.jsonify(traffic)

# login TrafficSchema http basic auth
@app.route('/traffic_login', methods=['POST'])
def login_traffic():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    traffic = Traffic.query.filter_by(contact=auth.username).first()

    if not traffic:
        return make_response('Could not verify2', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(traffic.password, auth.password):
        token = jwt.encode({'id': traffic.contact, 'role': "traffic"}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8'), 'contact': traffic.contact, 'name': traffic.name, 'role': 'Traffic'})

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