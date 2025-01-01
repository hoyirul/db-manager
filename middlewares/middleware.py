from functools import wraps
from flask import session, redirect, url_for

class AuthMiddleware:
    @staticmethod
    def authorized(f):
      @wraps(f)
      def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
          return redirect('/login')
        return f(*args, **kwargs)
      return decorated_function

    @staticmethod
    def unauthorized(f):
      @wraps(f)
      def decorated_function(*args, **kwargs):
        if 'logged_in' in session:
          return redirect('/')
        return f(*args, **kwargs)
      return decorated_function