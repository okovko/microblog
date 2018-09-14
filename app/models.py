from datetime import datetime
from time import time
from hashlib import md5
from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from flask_login import UserMixin
import jwt
from app.search import add_to_index, remove_from_index, query_index

class SearchableMixin(object):
    @classmethod
    def search(cls, exp, page, per_page):
        ids, total = query_index(cls.__tablename__, exp, page, per_page)
        if total == 0:
            return cls.query.filter_by(id = 0), 0
        when = [(idx, id) for idx, id in enumerate(ids)]
        results = cls.query.filter(cls.id.in_(ids)).order_by(
            db.case(when, value = cls.id)
        )
        return results, total
    
    @classmethod
    def before_commit(cls, session):
        session._changes = {
            'add' : list(session.new),
            'update' : list(session.dirty),
            'delete' : list(session.deleted),
        }
        
    @classmethod
    def after_commit(cls, session):
        for obj in [v for k, v in session._changes.items() if k in ['add', 'update']]:
            if isinstance(obj, SearchableMixin):
                add_to_index(obj.__tablename__, obj)
        for obj in session._changes['delete']:
            if isinstance(obj, SearchableMixin):
                remove_index(obj.__tablename__, obj)

    @classmethod
    def reindex(cls):
        for obj in cls.query:
            add_to_index(cls.__tablename__, obj)
            
db.event.listen(db.session, 'before_commit', SearchableMixin.before_commit)
db.event.listen(db.session, 'after_commit', SearchableMixin.after_commit)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

followers = db.Table('followers',
        db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
        db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
        )

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), index = True, unique = True)
    email = db.Column(db.String(120), index = True, unique = True)
    password_hash = db.Column(db.String(128))
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default = datetime.utcnow)
    posts = db.relationship('Post', backref = 'author', lazy = 'dynamic')
    followed = db.relationship(
            'User',
            secondary = followers,
            primaryjoin = (followers.c.follower_id == id),
            secondaryjoin = (followers.c.followed_id == id),
            backref = db.backref('followers', lazy = 'dynamic'),
            lazy = 'dynamic'
            )

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
                followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        followed = Post.query.join(
                followers, (followers.c.followed_id == Post.user_id)).filter(
                        followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id = self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def get_password_reset_token(self, expires_in = 600):
        return jwt.encode(
                {'password_reset' : self.id, 'exp' : time() + expires_in},
                current_app.config['SECRET_KEY'],
                algorithm = 'HS256'
        ).decode('utf-8')

    @staticmethod
    def verify_password_reset_token(token):
        try:
            user_id = jwt.decode(
                    token,
                    current_app.config['SECRET_KEY'],
                    algorithms = ['HS256'],
            )['password_reset']
        except:
            return None
        return User.query.get(user_id)

class Post(SearchableMixin, db.Model):
    __searchable__ = ['body']
    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index = True, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    language = db.Column(db.String(5))

    def __repr__(self):
        return '<Post {}>'.format(self.body)
