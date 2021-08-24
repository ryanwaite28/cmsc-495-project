import sys, os, string, random, psycopg2, sqlite3

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Float, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, backref, scoped_session
from sqlalchemy import create_engine
from sqlalchemy.sql import func
from sqlalchemy.sql.sqltypes import TIMESTAMP



Base = declarative_base()

class Users(Base):
  __tablename__ = 'users'

  id                         = Column(Integer, primary_key = True)
  displayname                = Column(String(80), nullable = False)
  username                   = Column(String(80), nullable = False)
  password                   = Column(String(80), nullable = False)
  bio                        = Column(String(250), default = '')
  icon_link                  = Column(String, default = '')
  icon_id                    = Column(String, default = '')
  date_created               = Column(TIMESTAMP(timezone = True), server_default = func.now())
  last_loggedin              = Column(TIMESTAMP(timezone = True), server_default = func.now())
  last_read_notifications    = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'displayname': self.displayname,
      'username': self.username,
      'bio': self.bio,
      'icon_link': self.icon_link,
      'icon_id': self.icon_id,
      'date_created': str(self.date_created),
      'last_loggedin': str(self.last_loggedin),
      'last_read_notifications': str(self.last_read_notifications),
    }



class Follows(Base):
  __tablename__ = 'follows'

  id                  = Column(Integer, primary_key = True)
  user_id             = Column(Integer, ForeignKey('users.id'))
  user_rel            = relationship('Users', foreign_keys=[user_id])
  follows_id          = Column(Integer, ForeignKey('users.id'))
  follows_rel         = relationship('Users', foreign_keys=[follows_id])
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    # Returns Data Object In Proper Format
    return {
      'id': self.id,
      'user': self.user_rel.serialize if self.user_rel else None,
      'follows': self.follows_rel.serialize if self.follows_rel else None,
      'date_created': str(self.date_created),
    }


class Posts(Base):
  __tablename__ = 'posts'

  id                  = Column(Integer, nullable = False, primary_key = True)
  owner_id            = Column(Integer, ForeignKey('users.id'))
  owner_rel           = relationship('Users')
  title               = Column(String, nullable = False)
  body                = Column(Text, nullable = False)
  hashtags            = Column(String, default = '')
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())
  last_updated        = Column(TIMESTAMP(timezone = True), server_default = func.now(), onupdate = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'owner': self.owner_rel.serialize if self.owner_rel else None,
      'title': self.title,
      'body': self.body,
      'hashtags': self.hashtags,
      'hashtags_list': self.hashtags.split(','),
      'date_created': str(self.date_created),
      'last_updated': str(self.last_updated),
    }



class PostLikes(Base):
  __tablename__ = 'post_likes'

  id                  = Column(Integer, nullable = False, primary_key = True)
  owner_id            = Column(Integer, ForeignKey('users.id'))
  owner_rel           = relationship('Users')
  post_id             = Column(Integer, ForeignKey('posts.id'))
  post_rel            = relationship('Posts')
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'owner': self.owner_rel.serialize if self.owner_rel else None,
      'post_id': self.post_id,
      'date_created': str(self.date_created),
    }



class Comments(Base):
  __tablename__ = 'comments'

  id                  = Column(Integer, nullable = False, primary_key = True)
  owner_id            = Column(Integer, ForeignKey('users.id'))
  owner_rel           = relationship('Users')
  post_id             = Column(Integer, ForeignKey('posts.id'))
  post_rel            = relationship('Posts')
  body                = Column(Text, nullable = False)
  hashtags            = Column(String(80), default = '')
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())
  last_updated        = Column(TIMESTAMP(timezone = True), server_default = func.now(), onupdate = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'owner': self.owner_rel.serialize if self.owner_rel else None,
      'post_id': self.post_id,
      'body': self.body,
      'hashtags': self.hashtags,
      'date_created': str(self.date_created),
      'last_updated': str(self.last_updated),
    }



class CommentLikes(Base):
  __tablename__ = 'comment_likes'

  id                  = Column(Integer, nullable = False, primary_key = True)
  owner_id            = Column(Integer, ForeignKey('users.id'))
  owner_rel           = relationship('Users')
  comment_id          = Column(Integer, ForeignKey('comments.id'))
  comment_rel         = relationship('Comments')
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'owner': self.owner_rel.serialize if self.owner_rel else None,
      'comment_id': self.comment_id,
      'date_created': str(self.date_created),
    }



class Messagings(Base):
  __tablename__ = 'messagings'

  id                  = Column(Integer, nullable = False, primary_key = True)
  user_id             = Column(Integer, ForeignKey('users.id'))
  user_rel            = relationship('Users', foreign_keys=[user_id])
  sender_id           = Column(Integer, ForeignKey('users.id'))
  sender_rel          = relationship('Users', foreign_keys=[sender_id])
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())
  last_updated        = Column(TIMESTAMP(timezone = True), server_default = func.now(), onupdate = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'user': self.user_rel.serialize if self.user_rel else None,
      'sender': self.sender_rel.serialize if self.sender_rel else None,
      'date_created': str(self.date_created),
      'last_updated': str(self.last_updated),
    }


class MessagingUserLastOpens(Base):
  __tablename__ = 'messaging_user_last_opens'

  id                  = Column(Integer, nullable = False, primary_key = True)
  messaging_id        = Column(Integer, ForeignKey('messagings.id'))
  messaging_rel       = relationship('Messagings', foreign_keys=[messaging_id])
  user_id             = Column(Integer, ForeignKey('users.id'))
  user_rel            = relationship('Users', foreign_keys=[user_id])
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())
  user_last_opened    = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'messaging': self.messaging_rel.serialize if self.messaging_rel else None,
      'user_id': self.user_id,
      'date_created': str(self.date_created),
      'user_last_opened': str(self.user_last_opened),
    }


class Messages(Base):
  __tablename__ = 'messages'

  id                  = Column(Integer, nullable = False, primary_key = True)
  from_id             = Column(Integer, ForeignKey('users.id'))
  from_rel            = relationship('Users', foreign_keys=[from_id])
  to_id               = Column(Integer, ForeignKey('users.id'))
  to_rel              = relationship('Users', foreign_keys=[to_id])
  body                = Column(Text, nullable = False)
  read                = Column(Boolean, default = False)
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'body': self.body,
      "read": self.read,
      'from': self.from_rel.serialize if self.from_rel else None,
      'to': self.to_rel.serialize if self.to_rel else None,
      'date_created': str(self.date_created),
    }



class Notifications(Base):
  __tablename__ = 'notifications'

  id                  = Column(Integer, nullable = False, primary_key = True)
  from_id             = Column(Integer, ForeignKey('users.id'))
  from_rel            = relationship('Users', foreign_keys=[from_id])
  to_id               = Column(Integer, ForeignKey('users.id'))
  to_rel              = relationship('Users', foreign_keys=[to_id])
  event               = Column(String, nullable = False)
  target_type         = Column(String, nullable = False)
  target_id           = Column(String, nullable = False)
  read                = Column(Boolean, default = False)
  date_created        = Column(TIMESTAMP(timezone = True), server_default = func.now())

  @property
  def serialize(self):
    return {
      'id': self.id,
      'from': self.from_rel.serialize if self.from_rel else None,
      'to': self.to_rel.serialize if self.to_rel else None,
      'event': self.event,
      'target_type': self.target_type,
      'target_id': self.target_id,
      'read': self.read,
      'date_created': str(self.date_created),
    }



# --- Create Database Session --- #

sqlite_file = "sqlite:///database.db?check_same_thread=False"
db_string = os.environ.get('DATABASE_URL', sqlite_file)
app_state = ''

if db_string[:8] == 'postgres':
  app_state = 'production'
  print('--- production ---')
else:
  app_state = 'development'
  print('--- development ---')

engine = create_engine(db_string, echo=True)
Base.metadata.create_all(engine)
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
Scoped_Session = scoped_session(DBSession)
db_session = Scoped_Session()
