from flask import render_template

class ErrorHelper:
    def not_found_error(self, error):
        e = {
            'code': 404,
            'message': 'Not Found',
            'description': 'The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.'
        }
        return render_template('errors/error.html', e=e), 404

    def internal_error(self, error):
        e = {
            'code': 500,
            'message': 'Internal Server Error',
            'description': 'The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.'
        }
        return render_template('errors/error.html', e=e), 500

    def method_not_allowed(self, error):
        e = {
            'code': 405,
            'message': 'Method Not Allowed',
            'description': 'The method is not allowed for the requested URL.'
        }
        return render_template('errors/error.html', e=e), 405

    def bad_request(self, error):
        e = {
            'code': 400,
            'message': 'Bad Request',
            'description': 'The browser (or proxy) sent a request that this server could not understand.'
        }
        return render_template('errors/error.html', e=e), 400