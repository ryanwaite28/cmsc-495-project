# --- Modules/Functions --- #

import os, re, jwt, json, html, bcrypt, queue
from functools import wraps
from dotenv import load_dotenv

from flask import Flask, Response, make_response, request, jsonify
from sqlalchemy.sql import func
from sqlalchemy import desc, asc

from cloudinary import config as cloudinary_config
from cloudinary.uploader import upload as cloudinary_upload
from cloudinary.utils import cloudinary_url

from models import db_session
from models import Users, Follows, Posts, PostLikes, Comments
from models import CommentLikes, Messagings, Messages, Notifications



# --- Setup --- #

load_dotenv()

CLOUDINARY_URL = os.getenv('CLOUDINARY_URL')
CLOUDINARY_API_KEY = os.getenv('CLOUDINARY_API_KEY')
CLOUDINARY_API_SECRET = os.getenv('CLOUDINARY_API_SECRET')
CLOUDINARY_CLOUD_NAME = os.getenv('CLOUDINARY_CLOUD_NAME')
cloudinary_env_proper = (
  CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET and CLOUDINARY_CLOUD_NAME
)
if cloudinary_env_proper:
  cloudinary_config(
    cloud_name = CLOUDINARY_CLOUD_NAME, 
    api_key = CLOUDINARY_API_KEY, 
    api_secret = CLOUDINARY_API_SECRET
  )
  print('cloudinary configured successfully')

class MessageAnnouncer:
  '''
  Server-Sent Events

  examples found here:
  https://maxhalford.github.io/blog/flask-sse-no-deps/
  '''

  def __init__(self):
    self.listeners = []

  def listen(self):
    q = queue.Queue(maxsize = 7)
    self.listeners.append(q)
    return q

  def push(self, msg):
    for i in reversed(range(len(self.listeners))):
      try:
        self.listeners[i].put_nowait(msg)
      except queue.Full:
        del self.listeners[i]

def format_sse(data, event = None):
  msg = f'data: {data}\n\n'
  if event is not None:
    msg = f'event: {event}\n{msg}'
  return msg


SSE = MessageAnnouncer()


app = Flask(__name__)
app.config['SECRET_KEY'] = '6Y#6G1$56F)$JD8*4G!?/Eoift4gk%&^(N*(|]={;96dfs3TYD5$)F&*DFj/YDR'


event_types = {
  "NEW_FOLLOWER": "NEW_FOLLOWER",
  "NEW_MESSAGE": "NEW_MESSAGE",
  "POST_COMMENT": "POST_COMMENT",
  "POST_LIKE": "POST_LIKE",
  "COMMENT_LIKE": "COMMENT_LIKE",
}

target_types = {
  "USER": "USER",
  "MESSAGE": "MESSAGE",
  "POST": "POST",
  "COMMENT": "COMMENT",
}



def make_jwt(data):
  try:
    token = jwt.encode(payload = data, key = app.config['SECRET_KEY'], algorithm = 'HS256')
    return token
  except Exception as error:
    print('make_jwt error:', error)
    return None


def decode_jwt(token):
  try:
    data = jwt.decode(token, key = app.config['SECRET_KEY'], algorithms=['HS256'])
    return data
  except Exception as error:
    print('decode_jwt error:', error)
    return None


def check_request_auth():
  if 'Authorization' not in request.headers:
    return make_response({ "message": "Authorization header required" }, 400)
  Authorization = request.headers['Authorization']
  if not Authorization:
    return make_response({ "message": "Authorization header cannot be empty" }, 400)
  if not re.match("^Bearer\s(.*)$", Authorization):
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
    if isinstance(data, Response):
      return data
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



def fill_notification(notification_obj):
  from_user = notification_obj['from']
  from_user_prefix = "[unknown/deleted user]" if not from_user else from_user['username']

  if notification_obj.event == event_types["NEW_FOLLOWER"]:
    message = f'{from_user_prefix} started following you.'
    notification_obj['message'] = message

  if notification_obj.event == event_types["NEW_MESSAGE"]:
    message = f'{from_user_prefix} sent you a message.'
    notification_obj['message'] = message

  if notification_obj.event == event_types["POST_COMMENT"]:
    message = f'{from_user_prefix} commented on your post.'
    notification_obj['message'] = message
    post = db_session.query(Posts).filter(Posts.id == notification_obj.target_id).first()
    if post:
      notification_obj['post'] = post.serialize

  if notification_obj.event == event_types["POST_LIKE"]:
    message = f'{from_user_prefix} liked your post.'
    notification_obj['message'] = message
    post = db_session.query(Posts).filter(Posts.id == notification_obj.target_id).first()
    if post:
      notification_obj['post'] = post.serialize

  if notification_obj.event == event_types["COMMENT_LIKE"]:
    message = f'{from_user_prefix} liked your comment.'
    notification_obj['message'] = message
    comment = db_session.query(Comments).filter(Comments.id == notification_obj.target_id).first()
    if comment:
      notification_obj['comment'] = comment.serialize

  return notification_obj



# --- GET Routes --- #


# Users

@app.route('/', methods=['GET'])
def root_toute():
  return make_response({ "message": "Blog Application" }, 200)
  
@app.route('/test-make-jwt', methods=['GET'])
def test_make_jwt():
  data = make_jwt({ "message": "Admit One" })
  print(data)
  return make_response({ "results": data }, 200)

@app.route('/listen', methods=['GET'])
def listen():
  def stream():
    messages = SSE.listen()  # returns a queue.Queue
    while True:
      msg = messages.get()  # blocks until a new message arrives
      yield msg
  return Response(stream(), mimetype = 'text/event-stream')


@app.route('/ping')
def ping():
  msg = format_sse(data = 'pong')
  SSE.push(msg = msg)
  SSE.push(msg = format_sse(data = 'admit one', event = 'FOR-USER:1'))
  SSE.push(msg = format_sse(data = json.dumps({ "message": "admit one" }), event = 'FOR-USER:1'))
  return {}, 200


@app.route('/publish', methods=['POST'])
def publish():
  '''
  route for testing SSE
  '''
  
  print(request.data.decode("utf-8"))
  msg = format_sse(data = request.data.decode("utf-8"))
  SSE.push(msg = msg)
  return { "message": "Admit One" }, 200


@app.route('/events')
def index():
  '''
  page for testing SSE
  '''
	
  return """<head>
    <script src="https://cdn.socket.io/3.1.3/socket.io.min.js" integrity="sha384-cPwlPLvBTa3sKAgddT6krw0cJat7egBga3DJepJyrLl4Q9/5WLra3rrnMcyTyOnh" crossorigin="anonymous"></script>
    </head>
    <body>
      <script>
        var eventSource = new EventSource('/listen');

        eventSource.onmessage = function(m) {
          console.log(m);
          var el = document.getElementById('messages');
          el.innerHTML += m.data;
          el.innerHTML += "</br>";
        }

        eventSource.addEventListener("FOR-USER:1", function(e) {
          console.log(e)
        })

        function post(url, data) {
          var request = new XMLHttpRequest();
          request.open('POST', url, true);
          // request.setRequestHeader('Content-Type', 'text/plain; charset=UTF-8');
          request.send(data);
        }

        function publish() {
          var message = document.getElementById("msg").value;
          post('/publish', message);
        }
      </script>
      <input type="text" id="msg">
      <button onclick="publish()">send</button>
      <p id="messages"></p>
    </body>"""


@app.route('/check_session', methods=['GET'])
def check_session():
  data = check_request_auth()
  result = jsonify(data = None) if not data else data
  return result


@app.route('/users/all', methods=['GET'])
def get_users_all():
  users = db_session.query(Users).order_by(desc(Users.id)).all()
  users_data = [u.serialize for u in users]
  return jsonify(users = users_data)


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
  user = db_session.query(Users).filter_by(id = user_id).first()
  return jsonify(user = user)


@user_authorized
@app.route('/users/<int:user_id>/notifications', methods=['GET'])
def get_user_notifications(user_id):
  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url"}, 400)
  
  notifications = db_session.query(Notifications).filter_by(to_id = user_id).all()
  notifications_data = [fill_notification(n.serialize) for n in notifications]
  return jsonify(notifications = notifications_data)


@user_authorized
@app.route('/users/<int:user_id>/messagings', methods=['GET'])
def get_user_messagings(user_id):
  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url"}, 400)

  format_messagings = lambda m: {
    "id": m.id,
    "date_created": m.date_created,
    "you": m.user_rel.serialize if m.user_id == user_id else m.sender_rel.serialize,
    "other": m.sender_rel.serialize if m.user_id == user_id else m.user_rel.serialize,
  }

  messagings = db_session.query(Messagings) \
    .filter((Messagings.user_id == user_id) | (Messagings.sender_id == user_id)) \
    .order_by(desc(Messagings.last_updated)) \
    .all()
  messagings_data = [format_messagings(m) for m in messagings]
  return jsonify(messagings = messagings_data)


@user_authorized
@app.route('/users/<int:user_id>/messagings/<int:other_id>/messages', methods=['GET'])
def get_user_messages_with_other_user(user_id, other_id):
  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url"}, 400)

  format_messages = lambda m: {
    "id": m.id,
    "date_created": m.date_created,
    "body": m.body,
    "read": m.read,
    "you": m.from_rel.serialize if m.from_id == user_id else m.to_rel.serialize,
    "other": m.to_rel.serialize if m.from_id == user_id else m.from_rel.serialize,
  }

  messages = db_session.query(Messages) \
    .filter((Messages.from_id == user_id) | (Messages.to_id == other_id)) \
    .filter((Messages.from_id == other_id) | (Messages.to_id == user_id)) \
    .order_by(asc(Messages.id)) \
    .all()

  messages_data = [format_messages(m) for m in messages]
  return jsonify(messages = messages_data)


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

@app.route('/posts/all', methods=['GET'])
def get_posts_all():
  posts = db_session.query(Posts).order_by(desc(Posts.id)).all()
  posts_data = [p.serialize for p in posts]
  return jsonify(posts = posts_data)


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
@app.route('/posts', methods=['POST'])
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

  return jsonify(message = "New Post Created!", post = new_post.serialize)


@user_authorized
@app.route('/posts/<int:post_id>/comments', methods=['POST'])
def create_comment(post_id):
  user = check_request_auth()
  data = json.loads(request.data)

  if "body" not in data:
    return make_response({"message": "Body field is required"}, 400)
  body = html.escape(data['body'])
  if not isinstance(body, str):
    return make_response({"message": "Body field must be string"}, 400)
  if not body or body == '':
    return make_response({"message": "Body field cannot be empty"}, 400)

  post = db_session.query(Posts).filter(Posts.id == post_id).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

  new_comment = Comments(owner_id = user['id'], post_id = post_id, body = body)

  if 'hashtags' in data:
    if not isinstance(data['hashtags'], list):
      return make_response({"message": "Hashtags field must be a list of strings"}, 400)
    for tag in data['hashtags']:
      if not isinstance(tag, str):
        return make_response({"message": "Tag \"" + str(tag) + "\" must be string"}, 400)
    
    hashtags_str = ','.join(data['hashtags'])
    new_comment.hashtags = hashtags_str

  if post.owner_id != user['id']:
    new_notification = Notifications(
      from_id = user['id'],
      to_id = post.owner_id,
      event = event_types["POST_COMMENT"],
      target_type = target_types["POST"],
      target_id = post_id,
    )
    db_session.add(new_notification)

  db_session.add(new_comment)
  db_session.commit()

  if post.owner_id != user['id']:
    event_name = f'FOR-USER:{post.owner_id}'
    event_data = json.dumps(new_notification.serialize)
    event_msg = format_sse(event_data, event_name)
    SSE.push(event_msg)

  return jsonify(message = "New Comment Created!", comment = new_comment.serialize)


@user_authorized
@app.route('/users/<int:user_id>/messagings/<int:other_user_id>/messages', methods=['POST'])
def create_user_messages_with_other_user(user_id, other_user_id):
  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url."}, 400)

  if user_id == other_user_id:
    return make_response({"message": "Users cannot message themselves."}, 400)

  data = json.loads(request.data)

  if "body" not in data:
    return make_response({"message": "Body field is required"}, 400)
  body = html.escape(data['body'])
  if not isinstance(body, str):
    return make_response({"message": "Body field must be string"}, 400)
  if not body or body == '':
    return make_response({"message": "Body field cannot be empty"}, 400)

  messaging = db_session.query(Messagings) \
    .filter((Messagings.user_id == user_id) | (Messagings.sender_id == other_user_id)) \
    .filter((Messagings.user_id == other_user_id) | (Messagings.sender_id == user_id)) \
    .order_by(desc(Messagings.last_updated)) \
    .all()

  if not messaging:
    messaging = Messagings(user_id = other_user_id, sender_id = user_id)
    db_session.add(messaging)
    db_session.commit()
  else:
    messaging.last_updated = func.now()
    db_session.add(messaging)
    db_session.commit()

  message = Messages(from_id = user_id, to_id = other_user_id, body = body)
  new_notification = Notifications(
    from_id = user_id,
    to_id = other_user_id,
    event = event_types["NEW_MESSAGE"],
    target_type = target_types["USER"],
    target_id = other_user_id,
  )

  db_session.add(new_notification)
  db_session.add(message)
  db_session.commit()

  event_name = f'FOR-USER:{other_user_id}'
  event_data = json.dumps(new_notification.serialize)
  event_msg = format_sse(event_data, event_name)
  SSE.push(event_msg)

  return jsonify(message = "New Message Sent!", data = message.serialize)




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
  if not cloudinary_env_proper:
    return make_response({"message": "Upload service unavailable at this time."}, 503)

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
@app.route('/posts/<int:post_id>', methods=['PUT'])
def update_post(post_id):
  user = check_request_auth()
  data = json.loads(request.data)

  post = db_session.query(Posts).filter(Posts.id == post_id).filter(Posts.owner_id == user['id']).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

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

  post.title = title
  post.body = body

  if 'hashtags' in data:
    if not isinstance(data['hashtags'], list):
      return make_response({"message": "Hashtags field must be a list of strings"}, 400)
    for tag in data['hashtags']:
      if not isinstance(tag, str):
        return make_response({"message": "Tag \"" + str(tag) + "\" must be string"}, 400)
    
    hashtags_str = ','.join(data['hashtags'])
    post.hashtags = hashtags_str

  db_session.add(post)
  db_session.commit()

  return jsonify(message = "Post Updated!", post = post.serialize)


@user_authorized
@app.route('/posts/<int:post_id>/comments/<int:comment_id>', methods=['PUT'])
def update_comment(post_id, comment_id):
  user = check_request_auth()
  data = json.loads(request.data)

  post = db_session.query(Posts).filter(Posts.id == post_id).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

  comment = db_session.query(Comments).filter(Comments.id == comment_id).filter(Comments.owner_id == user['id']).first()
  if not comment:
    return make_response({ "message": "Comment does not exist with id " + str(comment) }, 404)

  if "body" not in data:
    return make_response({"message": "Body field is required"}, 400)
  body = html.escape(data['body'])
  if not isinstance(body, str):
    return make_response({"message": "Body field must be string"}, 400)
  if not body or body == '':
    return make_response({"message": "Body field cannot be empty"}, 400)

  comment.body = body

  if 'hashtags' in data:
    if not isinstance(data['hashtags'], list):
      return make_response({"message": "Hashtags field must be a list of strings"}, 400)
    for tag in data['hashtags']:
      if not isinstance(tag, str):
        return make_response({"message": "Tag \"" + str(tag) + "\" must be string"}, 400)
    
    hashtags_str = ','.join(data['hashtags'])
    comment.hashtags = hashtags_str

  db_session.add(comment)
  db_session.commit()

  return jsonify(message = "Comment Updated!", comment = comment.serialize)



@user_authorized
@app.route('/users/<int:user_id>/toggle-follow/<int:follows_id>', methods=['PUT'])
def toggle_user_follow(user_id, follows_id):
  '''
  Toggle user following another user.
  if user is following the other user, unfollow. 
  if user is NOT following the other user, follow
  '''
  
  if user_id == follows_id:
    return make_response({"message": "Users cannot follow themselves"}, 400)

  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url"}, 400)

  follow_user = db_session.query(Users).filter_by(id = follows_id).first()
  if not follow_user:
    return make_response({ "message": "User does not exist with id " + str(follows_id) }, 404)

  follows = db_session.query(Follows).filter_by(user_id = user_id).filter_by(follows_id = follows_id).first()

  if follows:
    # is following; unfollow
    db_session.delete(follows)
    db_session.commit()
    return jsonify(message = 'unfollowed', following = False)
  else:
    # is NOT following; follow and send notification
    new_follow = Follows(user_id = user_id, follows_id = follows_id)
    new_notification = Notifications(
      from_id = user_id,
      to_id = follows_id,
      event = event_types["NEW_FOLLOWER"],
      target_type = target_types["USER"],
      target_id = follows_id,
    )

    db_session.add(new_follow)
    db_session.add(new_notification)
    db_session.commit()

    event_name = f'FOR-USER:{follows_id}'
    event_data = json.dumps(new_notification.serialize)
    event_msg = format_sse(event_data, event_name)
    SSE.push(event_msg)

    return jsonify(message = 'followed', following = True)


@user_authorized
@app.route('/users/<int:user_id>/toggle-post-like/<int:post_id>', methods=['PUT'])
def toggle_user_post_like(user_id, post_id):
  '''
  Toggle user liking a post.
  if user likes post, unlike. 
  if user does NOT like post, like
  '''

  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url"}, 400)

  post = db_session.query(Posts).filter(Posts.id == post_id).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)

  likes = db_session.query(PostLikes).filter_by(owner_id = user_id).filter_by(post_id = post_id).first()

  if likes:
    # does like; unlike
    db_session.delete(likes)
    db_session.commit()
    return jsonify(message = 'un-liked post', liked = False)
  else:
    # does not like post; like and notify post owner
    new_like = PostLikes(owner_id = user_id, post_id = post_id)

    if post.owner_id != user_id:
      new_notification = Notifications(
        from_id = user_id,
        to_id = post.owner_id,
        event = event_types["POST_LIKE"],
        target_type = target_types["POST"],
        target_id = post_id,
      )
      db_session.add(new_notification)

    db_session.add(new_like)
    db_session.commit()

    if post.owner_id != user_id:
      event_name = f'FOR-USER:{post.owner_id}'
      event_data = json.dumps(new_notification.serialize)
      event_msg = format_sse(event_data, event_name)
      SSE.push(event_msg)

    return jsonify(message = 'liked post', liked = True)


@user_authorized
@app.route('/users/<int:user_id>/toggle-comment-like/<int:comment_id>', methods=['PUT'])
def toggle_user_comment_like(user_id, comment_id):
  '''
  Toggle user liking a comment.
  if user likes comment, unlike. 
  if user does NOT like comment, like
  '''

  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url"}, 400)

  comment = db_session.query(Comments).filter(Comments.id == comment_id).first()
  if not comment:
    return make_response({ "message": "Comment does not exist with id " + str(comment_id) }, 404)

  likes = db_session.query(CommentLikes).filter_by(owner_id = user_id).filter_by(comment_id = comment_id).first()

  if likes:
    # does like; unlike
    db_session.delete(likes)
    db_session.commit()
    return jsonify(message = 'un-liked comment', liked = False)
  else:
    # does not like comment; like and notify comment owner
    new_like = CommentLikes(owner_id = user_id, comment_id = comment_id)

    if comment.owner_id != user_id:
      new_notification = Notifications(
        from_id = user_id,
        to_id = comment.owner_id,
        event = event_types["COMMENT_LIKE"],
        target_type = target_types["COMMENT"],
        target_id = comment_id,
      )
      db_session.add(new_notification)

    db_session.add(new_like)
    db_session.commit()

    if comment.owner_id != user_id:
      event_name = f'FOR-USER:{comment.owner_id}'
      event_data = json.dumps(new_notification.serialize)
      event_msg = format_sse(event_data, event_name)
      SSE.push(event_msg)

    return jsonify(message = 'liked comment', liked = True)



# --- DELETE Routes --- #

@user_authorized
@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
  user = check_request_auth()
  if user_id != user['id']:
    return make_response({"message": "User id from auth does not match user id in url."}, 400)

  you = db_session.query(Users).filter(Users.id == user['id']).first()
  if not you:
    return make_response({ "message": "Users does not exist with id " + str(user_id) }, 404)
  db_session.delete(you)

  follows = db_session.query(Follows).filter((Follows.user_id == user_id) | (Follows.follows_id == user_id)).all()
  for f in follows:
    db_session.delete(f)

  db_session.commit()

  return jsonify(message = "User Account Deleted")


@user_authorized
@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
  user = check_request_auth()

  post = db_session.query(Posts).filter(Posts.id == post_id).filter(Posts.owner_id == user['id']).first()
  if not post:
    return make_response({ "message": "Post does not exist with id " + str(post_id) }, 404)
  db_session.delete(post)
  db_session.commit()

  return jsonify(message = "Post Deleted")


@user_authorized
@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
  user = check_request_auth()

  comment = db_session.query(Comments).filter(Comments.id == comment_id).filter(Comments.owner_id == user['id']).first()
  if not comment:
    return make_response({ "message": "Comment does not exist with id " + str(comment) }, 404)
  db_session.delete(comment)
  db_session.commit()

  return jsonify(message = "Comment Deleted")






if __name__ == '__main__':
  app.debug = True
  app.run(host = '0.0.0.0' , port = 5000)