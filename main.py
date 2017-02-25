#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re
import jinja2
import os
import hmac
import time
import random
import hashlib

from google.appengine.ext import db

secret = "imsosecret"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def hash_str(s):
    return hmac.new(secret,s).hexdigest()

def make_secure_val(s):
    return s + '|' + hash_str(s)

def check_secure_val(h):
    vals = h.split('|')
    if make_secure_val(vals[0]) == h:
        return vals[0]

def make_salt():
    string = ''
    for i in range (0,5):
        capital = random.randint(0,1)
        if capital == 1:
            x = random.randrange(65,90)
        else:
            x = random.randrange(97,122)
        string += chr(x)

    return string

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    return make_pw_hash(name, pw, h.split('|')[1]) == h

class User(db.Model):
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def render_front(self):
        time.sleep(0.1)
        posts = db.GqlQuery("select * from BlogPost order by created desc limit 10")

        self.render("blog_front.html", posts=posts)

    def get(self):
        self.render_front()

class SignupHandler(Handler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def get(self):
        name_val = self.request.cookies.get('name')
        if name_val:
            name = check_secure_val(name_val)
            if name:
                self.redirect('/welcome')
            else:
                self.write_blank_form()
        else:
            self.write_blank_form()

    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        user_ok = self.validate_username(user)
        secure_user = make_secure_val(user)
        user_exists = self.username_exists(secure_user)
        pass_ok = self.validate_password(password)
        pass_equals = self.equal_passwords(password, verify)
        email_ok = self.validate_email(email)

        params = {'user':user,'email':email,'invalid_user':'','invalid_pass':'','invalid_verify':'','invalid_email':''}

        if(user_ok and (not user_exists) and pass_ok and pass_equals and email_ok):
            secure_pw = make_pw_hash(user, password)
            self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/'%str(secure_user))
            new_user = User(name=secure_user, password=secure_pw, email=email)
            new_user.put()
            self.redirect('/welcome')
        else:
            if(not user_ok):
                params['invalid_user'] = 'That\'s not a valid username.'
            if(user_ok and user_exists):
                params['invalid_user'] = 'That user already exists.'
            if(not pass_ok):
                params['invalid_pass'] = 'That wasn\'t a valid password.'
            if(pass_ok and not pass_equals):
                params['invalid_verify'] = 'Your passwords didn\'t match.'
            if(not email_ok):
                params['invalid_email'] = 'That\'s not a valid e-mail.'

            self.write_form(user=params['user'], email=params['email'], invalid_user=params['invalid_user'],
                            invalid_pass=params['invalid_pass'], invalid_verify=params['invalid_verify'], invalid_email=params['invalid_email'])

    def write_form(self, user='', email='', invalid_user='', invalid_pass='', invalid_verify='', invalid_email=''):
        self.render("signup.html", user=user, email=email, invalid_user=invalid_user, invalid_pass=invalid_pass, invalid_verify=invalid_verify, invalid_email=invalid_email)

    def write_blank_form(self):
        self.render("signup.html")

    def escape_html(self, s):
        return cgi.escape(s, quote = True)

    def validate_username(self, user):
        return self.USER_RE.match(user)

    def username_exists(self, user):
        user_exists = db.GqlQuery('select * from User where name = \'%s\''%user)
        new_user = None
        for u in user_exists:
            new_user = u
        
        return new_user

    def validate_password(self, password):
        return self.PASS_RE.match(password)

    def equal_passwords(self, password, verify):
        return password == verify

    def validate_email(self, email):
        return (email == '' or self.EMAIL_RE.match(email))

class WelcomeHandler(Handler):
    def get(self):
        name_val = self.request.cookies.get('name')
        if name_val:
            name = check_secure_val(name_val)
            if name:
                self.render('welcome.html', user=name)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')

class NewPostHandler(Handler):
    def render_newpost(self, subject='', content='', error=''):
        self.render("newpost.html", subject=subject, content=content, error = error)

    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            b = BlogPost(subject = subject, content = content)
            key = b.put()

            time.sleep(0.1)
            id = key.id()
            self.redirect('/'+str(id))
        else:
            error = "We need a subject and some content!"
            self.render_newpost(subject=subject, content=content, error = error)

class PostHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("blogpost.html", subject=post.subject, content=post.content)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewPostHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler),
    (r'/([0-9]+)', PostHandler)
], debug=True)