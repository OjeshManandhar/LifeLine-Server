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
from sqlalchemy import exc

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
            return jsonify({'err' : 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Traffic.query.filter_by(contact = data['id']).first()
            users = Traffic.query.all()       
            for user in users:
                user_data = {}
                user_data['id'] = user.contact
                if user.contact == current_user.contact and data['role'] == "traffic":
                    actual_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'err' : 'Signature expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'err' : 'Invalid token'}), 401
        return f(actual_user, *args, **kwargs)
    return decorated

# Init traffic schema
traffic_schema = TrafficSchema()
traffics_schema = TrafficSchema(many=True)

# token auth
@app.route('/traffic_check_token', methods=['POST'])
@token_required
def traffic_check_token(user):
    if user:
        token = jwt.encode(
            {'id': user.contact, 'role': "traffic", 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=2)}, 
            app.config['SECRET_KEY'], 
        )
        return jsonify({'new_token': token.decode('UTF-8')})
    else:
        return jsonify({'err' : 'Invalid token'}), 401


# login TrafficSchema http basic auth
@app.route('/traffic_login', methods=['POST'])
def login_traffic():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Login credentials missing', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    traffic = Traffic.query.filter_by(contact=auth.username).first()

    if not traffic:
        return make_response('Phone number is not registered yet', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(traffic.password, auth.password):
        token = jwt.encode(
            {'id': user.contact, 'role': "traffic", 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=2)}, 
            app.config['SECRET_KEY'], 
        )
        return jsonify({'token': token.decode('UTF-8'), 'contact': traffic.contact, 'name': traffic.name, 'role': 'traffic'})

    return make_response('Phone number and Password does not match', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

# Traffic Sign up
@app.route('/traffic_signup', methods=['POST'])
def Sign_up_traffic():
    name = request.json['name']
    email = request.json['email']
    contact = request.json['contact']
    password = request.json['password']
    email_regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if(re.search(email_regex,email) and len(str(contact)) == 10 and len(password)>7): 
        hashed_password = generate_password_hash(password, method='sha256')
        new_traffic = Traffic(name, email, contact, hashed_password)
        traffic_db.session.add(new_traffic)
        try:
            traffic_db.session.commit()
        except exc.SQLAlchemyError as e:
            return jsonify({'message': str(e.__dict__['orig'])})
        return traffic_schema.jsonify(new_traffic)
    else:
        return jsonify({'err': 'Signup Unsuccessful invalid data'}), 401

@app.route('/traffic_pic/<contact>', methods=['POST'])
def update_traffic_pic(contact):
    # check if the post request has the file part\
    traffic = Traffic.query.filter_by(contact=contact).first()
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

# Get single traffics
@app.route('/traffic/<contact>', methods=['GET'])
# @token_required
def get_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    return traffic_schema.jsonify(traffic)


# Get Traffics
@app.route('/traffic', methods=['GET'])
def get_traffics():
    all_traffics = Traffic.query.all()
    result = traffics_schema.dump(all_traffics)  # array vayeko le
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

# Get Traffic pic
@app.route('/traffic_pic/<contact>', methods=['GET'])
def get_traffic_pic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    if   traffic.pic_location:
        return send_file(traffic.pic_location)
    else:
        response = jsonify({'err': 'Image not found'})
        return response , 404

# Get Traffic small pic
@app.route('/traffic_small_pic/<contact>', methods=['GET'])
def traffic_small_pic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    if (not traffic.pic_location):
        response = jsonify({'err': 'Image not found'})
        return response, 404
        
    image = Image.open(traffic.pic_location)
    new_image = image.resize((100, 100))
    buff = BytesIO()
    new_image.save(buff, format="JPEG")
    img_str = base64.b64encode(buff.getvalue())
    return b'data:image/jpg;base64,'+img_str

# Update a Traffic
@app.route('/traffic/<contact>', methods=['PUT'])
#@token_required
def update_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()

    if not traffic:
        response = jsonify({'err': 'no traffic found'})
        return response, 404

    if traffic.contact != request.json['contact']:
        pic_loc = os.path.join(basedir, "User_pics/traffic",
                           (str(request.json['contact'])+traffic.pic_location[-4:]))
        os.rename(traffic.pic_location,pic_loc)
        traffic.put_pic_loc(pic_loc)
    traffic.update_data(request.json['name'], request.json['email'], request.json['contact'])
    traffic_db.session.commit()

    return traffic_schema.jsonify(traffic)

# Update a Traffic password
@app.route('/traffic_password/<contact>', methods=['PUT'])
#@token_required
def update_traffic_password(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()

    if not traffic:
        response = jsonify({'err': 'no traffic found'})
        return response, 404

    if traffic.contact != request.json['contact']:
        pic_loc = os.path.join(basedir, "User_pics/traffic",
                           (str(request.json['contact'])+traffic.pic_location[-4:]))
        os.rename(traffic.pic_location,pic_loc)
        traffic.put_pic_loc(pic_loc)

    password = hashed_password = generate_password_hash(request.json['password'], method='sha256')
    traffic.update_password(password)
    traffic_db.session.commit()

    return traffic_schema.jsonify(traffic)

# Delete traffics
@app.route('/traffic/<contact>', methods=['DELETE'])
def delete_traffic(contact):
    traffic = Traffic.query.filter_by(contact=contact).first()
    if not traffic:
        return jsonify({'err': 'no traffic found'}), 404
    try:
        os.remove(traffic.pic_location)
    except:
        print("no_pic-")
    traffic_db.session.delete(traffic)
    traffic_db.session.commit()
    return traffic_schema.jsonify(traffic)

