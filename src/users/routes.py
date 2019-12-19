# -*- coding: utf-8 -*-
import uuid
from flask import (
    Blueprint,
    request,
    jsonify,
    make_response
)
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

#--------
from src.orm import User, UpgradeRequest
from src import app, db
from src.helpers import token_required
#---------

users = Blueprint('users', __name__)

# login 

@users.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'basic realm="login Required!"'})
    
    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'basic realm="login Required!"'})

    if check_password_hash(user.pasword, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
            app.config['SECRET_KEY']
            )
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'basic realm="login Required!"'})


# register an normal user

@users.route('/user/register', methods=['POST'])
def create_user():
    data = request.get_json()
    public_id = str(uuid.uuid4())
    username = data['username']
    email = data['email']
    hashed_passwd = generate_password_hash(data['password'], method='sha256')
    new_user = User(
        public_id=public_id,
        username=username,
        email=email,
        pasword=hashed_passwd,
        is_curator=False,
        is_validator=False,
        is_admin=False
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(
            {'message': f'New account created for {username}!'}
        )
    except:
        return jsonify(
            {'message': f'Account creation failed!'}
        )


# register an admin user

@users.route('/user/register/admin', methods=['POST'])
def create_admin_user():
    data = request.get_json()
    public_id = str(uuid.uuid4())
    username = data['username']
    email = data['email']
    hashed_passwd = generate_password_hash(data['password'], method='sha256')
    new_user = User(
        public_id=public_id,
        username=username,
        email=email,
        pasword=hashed_passwd,
        is_curator=False,
        is_validator=False,
        is_admin=True
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(
            {'message': f'New admin account created for {username}!'}
        )
    except:
        return jsonify(
            {'message': f'Account creation failed!'}
        )


# request upgradation of account

@users.route('/user/request-upgrade', methods=['POST'])
@token_required
def request_upgrade(current_user):

    if current_user.is_curator:
        return jsonify({'message': 'You are already an annotator!'})
    elif current_user.is_validator:
        return jsonify({'message': 'You are aleady a validator'})
    elif current_user.is_admin:
        return jsonify({'message': 'You are aleady an admin'})

    data = request.get_json()

    if not data:
        return jsonify({'message': 'no request data received!'})


    
    user_id = current_user.id
    request_type = data['request_type']
    request_id = str(uuid.uuid4())

    new_request = UpgradeRequest(
        request_id=request_id,
        request_type=request_type,
        user_id=user_id,
        is_accepted=False,
        is_denied=False,
        under_processing=True
    )

    db.session.add(new_request)
    db.session.commit()
    
    return jsonify({
        'message': f'New {request_type} request has been submitted  for {current_user.username}!',
        'request_id': f'{request_id}'
        })


# process upgrade request

@users.route('/user/<request_id>/upgrade', methods=['PUT'])
@token_required
def make_curator(current_user, request_id):
    
    if not current_user.is_admin:
        return jsonify({'message': 'Operation is only allowed for admin'}), 403
        
    #request = UpgradeRequest.query.filter_by(request_id=request_id).first()
    request = db.session.query(UpgradeRequest).filter_by(request_id=request_id).first()

    if not request:
        return jsonify({'message': 'No request found with the specified id'})

    request_pk = request.id
    req_obj = UpgradeRequest.query.get(int(request_pk))
    
    request_type = request.request_type
    req_obj.is_accepted = True
    req_obj.under_processing = False
    request_user = req_obj.user_id
    user = User.query.get(int(request_user))

    if request_type == 'Curator':
        user.is_curator = True
    elif request_type == 'Validator':
        user.is_validator = True
    elif request_type == 'Admin':
        user.is_admin = True
    try:
        db.session.flush()
        return jsonify({
            'request_id': f'{request_id}',
            'request_type': f'{request_type}',
            'status': 'approved'
            })
    except:
        return jsonify({'message': 'database entry failed!'})


# revoke curator access

@users.route('/user/<public_id>/curator/revoke', methods=['PUT'])
@token_required
def revoke_curator(current_user, public_id):
    
    if not current_user.is_admin:
        return jsonify({'message': 'Operation is only allowed for admin'}), 403
    
    user = User.query.filter_by(public_id=public_id).first()
    if user:
        username = user.username
        if user.is_curator == True:
            user.is_curator = False
            db.session.commit()
            return jsonify(
                {'message': f'{username} is no longer an annotator!'}
            )
        else:
            return jsonify(
                {'message': f'operation not allowed for {username}!'}
            )
    else:
        return jsonify(
            {'message': f'No user found with the specified id'}
        )


# revoke validator access

@users.route('/user/<public_id>/validator/revoke', methods=['PUT'])
@token_required
def revoke_validator(current_user, public_id):

    if not current_user.is_admin:
        return jsonify({'message': 'Operation is only allowed for admin'}), 403


    user = User.query.filter_by(public_id=public_id).first()
    if user:
        username = user.username
        if user.is_validator == True:
            user.is_validator = False
            db.session.commit()
            return jsonify(
                {'message': f'{username} is no longer a validator!'}
            )
        else:
            return jsonify(
                {'message': f'operation not allowed for {username}!'}
            )
    else:
        return jsonify(
            {'message': f'No user found with the specified id'}
        )

# revoke admin access

@users.route('/user/<public_id>/admin/revoke', methods=['PUT'])
@token_required
def revoke_admin(current_user, public_id):

    if not current_user.is_admin:
        return jsonify({'message': 'Operation is only allowed for admin'}), 403

    user = User.query.filter_by(public_id=public_id).first()
    if user:
        username = user.username
        if user.is_admin == True:
            user.is_admin = False
            db.session.commit()
            return jsonify(
                {'message': f'{username} is no longer an admin!'}
            )
        else:
            return jsonify(
                {'message': f'operation not allowed for {username}!'}
            )
    else:
        return jsonify(
            {'message': f'No user found with the specified id'}
        )

# delete user account

@users.route('/user/<public_id>/delete', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.is_admin:
        return jsonify({'message': 'Operation is only allowed for admin'}), 403

    user = User.query.filter_by(public_id=public_id).first()
    if user:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        return jsonify(
        {'message': f'Account for {username} is deleted!'}
        )
    else:
        return jsonify(
            {'message': f'No user found with the specified id'}
        )



# get list of all registered uses

@users.route('/user/all', methods=['GET'])
@token_required
def get_all_users(current_user):
    output = []
    users = User.query.all()
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['is_curator'] = user.is_curator
        user_data['is_validator'] = user.is_validator
        user_data['is_admin'] = user.is_admin
        output.append(user_data)

    return jsonify(
        {'users': output}
    )


# get list of all upgrade request

@users.route('/user/request-upgrade/all', methods=['GET'])
@token_required
def get_all_requests(current_user):

    if not current_user.is_admin:
        return jsonify({'message': 'Route is only allowed for admin'}), 403

    output = []
    requests = UpgradeRequest.query.all()
    for request in requests:
        request_data = {}
        request_data['request_id'] = request.request_id
        request_data['UTC_timestamp'] = request.request_timestamp
        request_data['request_type'] = request.request_type
        request_data['is_accepted'] = request.is_accepted
        request_data['is_denied'] = request.is_denied
        request_data['under_processing'] = request.under_processing
        request_data['user'] = User.query.get(int(request.user_id)).username
        output.append(request_data)

        return jsonify(
            {'requests': output}
        )




    