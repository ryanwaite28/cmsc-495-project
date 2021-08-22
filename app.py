# --- Modules/Functions --- #

import re, json, string, random, html, bcrypt
import jwt

from functools import wraps
from datetime import timedelta
from threading import Timer

from flask import Flask, make_response, g, request, send_from_directory
from flask import render_template, url_for, redirect, flash, jsonify
from flask import session as user_session
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO
from sqlalchemy.sql import func
from sqlalchemy import desc, or_

import cloudinary
from cloudinary.uploader import upload as cloudinary_upload
from cloudinary.utils import cloudinary_url

from models import db_session
from models import Users, Follows, Posts, PostLikes, Comments
from models import CommentLikes, Messagings, Messages, Notifications



# --- Setup --- #

app = Flask(__name__)
app.config['SECRET_KEY'] = '6Y#6G1$56F)$JD8*4G!?/Eoift4gk%&^(N*(|]={;96dfs3TYD5$)F&*DFj/YDR'
socketio = SocketIO(app)


event_types = {
  "NEW_MESSAGING": "NEW_MESSAGING",
  "NEW_MESSAGE": "NEW_MESSAGE",
  "MESSAGING_EVENTS_SUBSCRIBED": "MESSAGING_EVENTS_SUBSCRIBED",
  "MESSAGING_EVENTS_UNSUBSCRIBED": "MESSAGING_EVENTS_UNSUBSCRIBED",
  "NEW_FOLLOWER": "NEW_FOLLOWER",
  "NEW_UNFOLLOWER": "NEW_UNFOLLOWER",
  "MESSAGE_TYPING": "MESSAGE_TYPING",
  "MESSAGE_TYPING_STOPPED": "MESSAGE_TYPING_STOPPED",
  "SOCKET_TRACK": "SOCKET_TRACK",
  "SOCKET_TO_USER_EVENT": "SOCKET_TO_USER_EVENT",
  "POST_LIKE": "POST_LIKE",
  "COMMENT_LIKE": "COMMENT_LIKE",
  "POST_COMMENT": "POST_COMMENT",
}

target_types = {
  "USER": "USER",
  "MESSAGING": "MESSAGING",
  "MESSAGE": "MESSAGE",
  "POST": "POST",
  "COMMENT": "COMMENT",
}



# def login_required(f):
#   ''' Checks If User Is Logged In '''
#   @wraps(f)
#   def decorated_function(*args, **kwargs):
#     if 'session_id' in user_session:
#       return f(*args, **kwargs)
#     else:
#       # flash('Please Log In To Use This Site.')
#       return redirect('/signin')
#   return decorated_function


# def ajax_login_required(f):
#   ''' Checks If User Is Logged In '''
#   @wraps(f)
#   def decorated_function(*args, **kwargs):
#     if 'session_id' in user_session:
#       return f(*args, **kwargs)
#     else:
#       return make_response({ "message": "Not signed in" }, 401)
#   return decorated_function


def make_jwt(data):
  try:
    token = jwt.encode(payload = data, key = app.config['SECRET_KEY'], algorithm = 'RS256')
    return token
  except jwt.exceptions.ExpiredSignatureError as error:
    print(error)
    return None


def decode_jwt(token):
  try:
    data = jwt.decode(token, key = app.config['SECRET_KEY'], algorithms=['RS256', ])
    return data
  except jwt.exceptions.ExpiredSignatureError as error:
    print(error)
    return None


def check_request_auth():
  Authorization = request.headers['Authorization']
  if not Authorization:
    return make_response({ "message": "Authorization header required" }, 400)
  if not re.match("(Bearer\s[^])", Authorization):
    return make_response({ "message": "Authorization header must be in Bearer format" }, 400)
  token = Authorization.split(' ')[1]
  data = decode_jwt(token)
  return data

def user_authorized(f):
  ''' Checks If User Is Logged In '''
  @wraps(f)
  def decorated_function(*args, **kwargs):
    data = check_request_auth()
    if not data:
      return make_response({ "message": "Bad jwt" }, 400)
    return f(*args, **kwargs)
  return decorated_function



def upload_file(file, old_id = None):
  try:
    if not file:
      return False

    upload_result = cloudinary_upload(file)
    thumbnail_url1, options = cloudinary_url(upload_result['public_id'], format="jpg", crop="fill", width=200, height=200)

    data_dict = {
      "upload_result": upload_result,
      "thumbnail_url1": thumbnail_url1,
      "options": options
    }

    return data_dict

  except Exception as e:
    print("error - ", e)
    return False



def fill_notification(notification):



  return notification






# --- GET Routes --- #


# Users

@app.route('/check_session', methods=['GET'])
def check_session():
  data = check_request_auth()
  return jsonify(data = data)


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
  user = db_session.query(Users).filter_by(id = user_id).first()
  return jsonify(user = user)


@app.route('/users/<int:user_id>/followers', methods=['GET'])
def get_user_followers(user_id):
  followers = db_session.query(Follows).filter_by(follows_id = user_id).all()
  followers_data = [f.serialize for f in followers]
  return jsonify(followers = followers_data)


@app.route('/users/<int:user_id>/followings', methods=['GET'])
def get_user_followings(user_id):
  followings = db_session.query(Follows).filter_by(user_id = user_id).all()
  followings_data = [f.serialize for f in followings]
  return jsonify(followings = followings_data)


@app.route('/users/<int:user_id>/check-follow/<int:follows_id>', methods=['GET'])
def check_user_following(user_id, follows_id):
  check = db_session.query(Follows).filter_by(user_id = user_id).filter_by(follows_id = follows_id).first()
  result = check.serialize if check is not None else None
  return jsonify(following = result)


@app.route('/users/<int:user_id>/check-post-like/<int:post_id>', methods=['GET'])
def check_user_post_like(user_id, post_id):
  check = db_session.query(PostLikes).filter_by(owner_id = user_id).filter_by(post_id = post_id).first()
  result = check.serialize if check is not None else None
  return jsonify(following = result)


@app.route('/users/<int:user_id>/check-comment-like/<int:comment_id>', methods=['GET'])
def check_user_comment_like(user_id, comment_id):
  check = db_session.query(CommentLikes).filter_by(owner_id = user_id).filter_by(comment_id = comment_id).first()
  result = check.serialize if check is not None else None
  return jsonify(following = result)



# Posts

@app.route('/users/<int:user_id>/posts/all', methods=['GET'])
def get_user_posts_all(user_id):
  user = db_session.query(Users).filter_by(id = user_id).first()
  if not user:
    return make_response({ "message": "User does not exist with id " + str(user_id) }, 400)

  posts = db_session.query(Posts).filter_by(owner_id = user_id).order_by(desc(Posts.id)).all()
  posts_data = [p.serialize for p in posts]
  return jsonify(posts = posts_data)


@app.route('/users/<int:user_id>/posts', methods=['GET'])
def get_user_posts(user_id):
  user = db_session.query(Users).filter_by(id = user_id).first()
  if not user:
    return make_response({ "message": "User does not exist with id " + str(user_id) }, 400)

  posts = db_session.query(Posts).filter_by(owner_id = user_id).order_by(desc(Posts.id)).limit(5).all()
  posts_data = [p.serialize for p in posts]
  return jsonify(posts = posts_data)


@app.route('/users/<int:user_id>/posts/paginate/<int:post_id>', methods=['GET'])
def get_user_posts_desc_id(user_id, post_id):
  user = db_session.query(Users).filter_by(id = user_id).first()
  if not user:
    return make_response({ "message": "User does not exist with id " + str(user_id) }, 400)

  posts = db_session.query(Posts).filter(Posts.owner_id == user_id).filter(Posts.id < post_id).order_by(desc(Posts.id)).limit(5).all()
  posts_data = [p.serialize for p in posts]
  return jsonify(posts = posts_data)


@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post_by_id(post_id):
  post = db_session.query(Posts).filter(Posts.id == post_id).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

  post_data = post.serialize
  return jsonify(post = post_data)


@app.route('/posts/<int:post_id>/likes', methods=['GET'])
def get_post_likes(post_id):
  post = db_session.query(Posts).filter(Posts.id == post_id).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

  post_likes = db_session.query(PostLikes).filter(PostLikes.post_id == post_id).all()
  post_likes_data = [p.serialize for p in post_likes]
  return jsonify(post_likes = post_likes_data)



# Comments

@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def get_post_comments(post_id):
  post = db_session.query(Posts).filter(Posts.id == post_id).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

  comments = db_session.query(Comments).filter(Comments.post_id == post_id).order_by(desc(Comments.id)).all()
  comments_data = [c.serialize for c in comments]
  return jsonify(comments = comments_data)


@app.route('/comments/<int:comment_id>', methods=['GET'])
def get_comment_by_id(comment_id):
  comment = db_session.query(Comments).filter(Comments.id == comment_id).first()
  if not comment:
    return make_response({ "message": "Comment does not exist with id " + str(comment) }, 404)

  comment_data = comment.serialize
  return jsonify(comment = comment_data)


@app.route('/comments/<int:comment_id>/likes', methods=['GET'])
def get_comment_likes(comment_id):
  comment = db_session.query(Comments).filter(Comments.id == comment_id).first()
  if not comment:
    return make_response({ "message": "Comment does not exist with id " + str(comment) }, 404)

  comment_likes = db_session.query(CommentLikes).filter(CommentLikes.comment_id == comment_id).all()
  comment_likes_data = [c.serialize for c in comment_likes]
  return jsonify(comment_likes = comment_likes_data)







# --- POST Routes --- #

@app.route('/sign_up', methods=['POST'])
def sign_up():
  data = json.loads(request.data)

  if "displayname" not in data:
    return make_response({"message": "Displayname field is required"}, 400)

  if "username" not in data:
    return make_response({"message": "Username field is required"}, 400)

  if "password" not in data:
    return make_response({"message": "Password field is required"}, 400)

  if "confirmpassword" not in data:
    return make_response({"message": "Confirm Password field is required"}, 400)

  displayname = html.escape(data['displayname'])
  username = html.escape(data['username'])
  password = html.escape(data['password']).encode('utf8')
  confirmpassword = html.escape(data['confirmpassword']).encode('utf8')

  if not re.match("([a-zA-Z][\w\-]+)", displayname):
    return make_response({"message": "Displayname must be numbers and letters only; underscores and dashes are allowed"}, 400)

  if not re.match("([a-zA-Z][\w\-]+)", username):
    return make_response({"message": "Username must be numbers and letters only; underscores and dashes are allowed"}, 400)

  if not password or len(password) < 5:
    return make_response({"message": "Password must be at least 5 characters"}, 400)

  if not confirmpassword:
    return make_response({"message": "Confirm Password must be at least 5 characters"}, 400)

  if password != confirmpassword:
    return make_response({"message": "Passwords must match"}, 400)

  check_username = db_session.query(Users).filter_by(username = username).first()
  if check_username:
    return make_response({"message": "Username already in use"}, 400)

  hash = bcrypt.hashpw(password, bcrypt.gensalt()).encode('utf8')
  new_user = Users(displayname = displayname, username = username, password = hash)
  db_session.add(new_user)
  db_session.commit()

  user_data = new_user.serialize
  new_token = make_jwt(user_data)

  return jsonify(message = "Signed Up!", user = user_data, token = new_token)


@user_authorized
@app.route('/create_post', methods=['POST'])
def create_post():
  user = check_request_auth()
  data = json.loads(request.data)

  if "title" not in data:
    return make_response({"message": "Title field is required"}, 400)
  title = html.escape(data['title'])
  if not isinstance(title, str):
    return make_response({"message": "Title field must be string"}, 400)
  if not title or title == '':
    return make_response({"message": "Title field cannot be empty"}, 400)

  if "body" not in data:
    return make_response({"message": "Body field is required"}, 400)
  body = html.escape(data['body'])
  if not isinstance(body, str):
    return make_response({"message": "Body field must be string"}, 400)
  if not body or body == '':
    return make_response({"message": "Body field cannot be empty"}, 400)

  new_post = Posts(owner_id = user['id'], title = title, body = body)

  if 'hashtags' in data:
    if not isinstance(data['hashtags'], list):
      return make_response({"message": "Hashtags field must be a list of strings"}, 400)
    for tag in data['hashtags']:
      if not isinstance(tag, str):
        return make_response({"message": "Tag \"" + str(tag) + "\" must be string"}, 400)
    
    hashtags_str = ','.join(data['hashtags'])
    new_post.hashtags = hashtags_str

  db_session.add(new_post)
  db_session.commit()

  return jsonify(message = "New Task Created!", post = new_post.serialize)




# --- PUT Routes --- #

@app.route('/sign_in', methods=['PUT'])
def sign_in():
  data = json.loads(request.data)

  if "username" not in data:
    return make_response({"message": "Username field is required"}, 400)

  if "password" not in data:
    return make_response({"message": "Password field is required"}, 400)

  username = html.escape(data['username'])
  password = html.escape(data['password']).encode('utf8')

  you = db_session.query(Users).filter_by(username = username).first()
  if not you:
    return make_response({"message": "Username not found"}, 400)

  checkPassword = bcrypt.hashpw(password, you.password.encode('utf8'))
  if checkPassword != you.password:
    return make_response({"message": "Invalid Credentials"}, 400)

  you.last_loggedin = func.now()
  db_session.add(you)
  db_session.commit()

  user_data = you.serialize
  new_token = make_jwt(user_data)

  return jsonify(message = "Signed In!", user = user_data, token = new_token)


@user_authorized
@app.route('/update_account', methods=['PUT'])
def update_account():
  data = json.loads(request.data) if request.data else None
  user = check_request_auth()

  you = db_session.query(Users).filter_by(id = user['id']).one()

  if not data:
    return make_response({"message": "No data found"}, 400)

  if "displayname" in data:
    displayname = html.escape(data['displayname'])
    if not re.match("([a-zA-Z][\w\-]+)", displayname):
      return make_response({"message": "Displayname must be numbers and letters only; underscores and dashes are allowed"}, 400)
    you.displayname = displayname
  
  if "username" in data:
    username = html.escape(data['username'])
    if not re.match("([a-zA-Z][\w\-]+)", username):
      return make_response({"message": "Username must be numbers and letters only; underscores and dashes are allowed"}, 400)
    check_username = db_session.query(Users).filter_by(username = username).first()
    if check_username:
      return make_response({"message": "Username already in use"}, 400)
    you.username = username

  if "bio" in data:
    bio = html.escape(data['bio'])
    you.bio = bio

  db_session.add(you)
  db_session.commit()

  user_data = you.serialize
  new_token = make_jwt(user_data)

  return jsonify(message = "Account Updated!", user = user_data, token = new_token)


@user_authorized
@app.route('/update_icon', methods=['PUT'])
def update_icon():
  file = request.files['icon_file']
  if not file:
    return make_response({"message": "File not found in request"}, 400)

  user = check_request_auth()
  you = db_session.query(Users).filter_by(id = user['id']).one()

  try:
    res = upload_file(file)

    icon_id = res["upload_result"]["public_id"]
    icon_url = res["upload_result"]["secure_url"]
    you.icon_link = icon_url
    you.icon_id = icon_id
    db_session.add(you)
    db_session.commit()

    user_data = you.serialize
    new_token = make_jwt(user_data)

    return jsonify(message = "Icon Updated!", user = user_data, token = new_token)

  except Exception as e:
    print('error - ', e)
    return make_response({"message": "could not upload image at this time"}, 500)


@user_authorized
@app.route('/update_post', methods=['PUT'])
def update_post():
  user = check_request_auth()
  data = json.loads(request.data)

  if "title" not in data:
    return make_response({"message": "Title field is required"}, 400)
  title = html.escape(data['title'])
  if not isinstance(title, str):
    return make_response({"message": "Title field must be string"}, 400)
  if not title or title == '':
    return make_response({"message": "Title field cannot be empty"}, 400)

  if "body" not in data:
    return make_response({"message": "Body field is required"}, 400)
  body = html.escape(data['body'])
  if not isinstance(body, str):
    return make_response({"message": "Body field must be string"}, 400)
  if not body or body == '':
    return make_response({"message": "Body field cannot be empty"}, 400)

  new_post = Posts(owner_id = user['id'], title = title, body = body)

  if 'hashtags' in data:
    if not isinstance(data['hashtags'], list):
      return make_response({"message": "Hashtags field must be a list of strings"}, 400)
    for tag in data['hashtags']:
      if not isinstance(tag, str):
        return make_response({"message": "Tag \"" + str(tag) + "\" must be string"}, 400)
    
    hashtags_str = ','.join(data['hashtags'])
    new_post.hashtags = hashtags_str

  db_session.add(new_post)
  db_session.commit()

  return jsonify(message = "New Task Created!", post = new_post.serialize)

# ---
# --- DELETE Routes --- #

@user_authorized
@app.route('/delete_account', methods=['DELETE'])
def delete_account():
    return DELETE.delete_account(request)



if __name__ == '__main__':
  app.debug = True
  socketio.run(app)