# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request, redirect
from flask_login import login_required
from jinja2 import TemplateNotFound
from apps.authentication.forms import LoginForm
import base64
import pickle
from apps.authentication.models import Users

from functools import wraps


def isBase64(sb):
    try:
        if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def check_oauth():
    def _check_oauth(f):
        @wraps(f)
        def __check_oauth(*args, **kwargs):
            # just do here everything what you need
            print('************ Checking authentication ************')
            auth = request.cookies.get('auth')
            if auth and isBase64(auth):
                try:
                    auth = pickle.loads(base64.b64decode(auth))
                    # print(auth)
                    if "username" in auth:
                        username = auth['username']
                        user = Users.query.filter_by(username=username).first()
                        if user:
                            result = f(*args, **kwargs)
                    else:
                        result = render_template('home/index.html')
                except Exception as e:
                    print(e)
                    result = redirect('logout')
            else:
                result = redirect('logout')
            return result
        return __check_oauth
    return _check_oauth


@blueprint.route('/index')
# @login_required
@check_oauth()
def index():
    return render_template('home/dashboard.html', segment='index')


@blueprint.route('/<template>')
# @login_required
@check_oauth()
def route_template(template):
    try:
        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
