#!/usr/bin/python
'''

>>> environ=dict(HTTPS='1',
...              SERVER_NAME='host.example',
...              REQUEST_METHOD='POST')
>>> io = MockIO(stdin='password=sekret')
>>> cwd = Path('.', io.ops())

>>> main(io.stdin, io.stdout, environ, cwd, io.now, io.FileSystemLoader)

>>> print io.stdout.getvalue()
... # doctest: +ELLIPSIS
Content-type: text/html
Set-Cookie: rumpelroot=...
<BLANKLINE>
... render rumpeltree.html with {'rumpelroot': 'KEM...'}
<BLANKLINE>
'''
from datetime import timedelta
import Cookie
import base64
import cgi
import hashlib
import hmac
import json

from jinja2 import Environment

# CHANGE THIS SALT WHEN INSTALLED ON YOUR PERSONAL SERVER!
serversalt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP"


def main(stdin, stdout, environ, cwd, now, FileSystemLoader):
    print >>stdout, "Content-type: text/html"

    path = (cwd / __file__).resolve().parent
    templateEnv = Environment(
        autoescape=False,
        loader=FileSystemLoader(str(path / 'templates')),
        trim_blocks=False)

    def render_template(template_filename, context):
        return templateEnv.get_template(template_filename).render(context)

    servername = None
    if "SERVER_NAME" in environ:
        servername = environ["SERVER_NAME"]
        html = ("<H2>OOPS</H2><b>YOU SHOULD NEVER</b> access ZeroVault "
                "over a <b>UNENCRYPTED</b> connection!<br>"
                "Please visit the <A HREF=\"https://" +
                servername + "/\">HTTPS site</A>!")
    else:
        html = "<H2>OOPS</H2>Broken server setup. No SERVER_NAME set."
    if "HTTPS" in environ:
        if "HTTP_COOKIE" in environ:
            print >>stdout
            cookie = Cookie.SimpleCookie(environ["HTTP_COOKIE"])
            rumpelroot = cookie["rumpelroot"].value
            rumpelsub = base64.b32encode(hmac.new(
                serversalt,
                rumpelroot,
                digestmod=hashlib.sha256).digest()).strip("=")
            revocationjsonfile = (cwd / ("../revoked/" + rumpelsub + ".json"))
            revocationlist = []
            if (revocationjsonfile.exists()):
                with revocationjsonfile.open(mode='rb') as data_file:
                    revocationlist = json.load(data_file)
            form = cgi.FieldStorage(fp=stdin, environ=environ)
            revocekey = "NONE"
            if "revocationkey" in form:
                revocekey = form["revocationkey"].value
                if len(revocekey) == 32:
                    revocationlist.append(revocekey)
                    with revocationjsonfile.open(mode='wb') as outfile:
                        json.dump(revocationlist, outfile)
            context = {
                'rumpelroot': rumpelroot,
                'revocationlist': revocationlist
            }
            html = render_template('rumpeltree.html', context)
        else:
            form = cgi.FieldStorage(fp=stdin, environ=environ)
            if "password" in form:
                rumpelroot = base64.b32encode(hmac.new(
                    serversalt,
                    msg=form["password"].value,
                    digestmod=hashlib.sha256).digest()).strip("=")
                cookie = Cookie.SimpleCookie()
                cookie["rumpelroot"] = rumpelroot
                cookie["rumpelroot"]["domain"] = "password.capibara.com"
                cookie["rumpelroot"]["path"] = "/"
                expiration = now() + timedelta(days=365 * 20)
                cookie["rumpelroot"]["expires"] = expiration.strftime(
                    "%a, %d-%b-%Y %H:%M:%S PST")
                print >>stdout, cookie.output()
                print >>stdout
                context = {
                  'rumpelroot': rumpelroot
                }
                html = render_template('rumpeltree.html', context)
            else:
                print >>stdout
                context = {}
                html = render_template('passwordform.html', context)
    else:
        print >>stdout
    print >>stdout, html


class Path(object):
    '''pathlib style file API

    ref https://pypi.python.org/pypi/pathlib2/
    '''
    def __init__(self, path, ops):
        self._path = path
        abspath, dirname, pathjoin, exists, io_open = ops
        self.resolve = lambda: Path(abspath(path), ops)
        self.pathjoin = lambda other: Path(pathjoin(path, other), ops)
        self._parent = lambda: Path(dirname(path), ops)
        self.exists = lambda: exists(path)
        self.open = lambda mode='r': io_open(path, mode=mode)

    @property
    def parent(self):
        return self._parent()

    def __str__(self):
        return self._path

    def __div__(self, other):
        return self.pathjoin(other)


class MockIO(object):
    def __init__(self, stdin=''):
        from io import BytesIO
        self.stdin = BytesIO(stdin)
        self.stdout = BytesIO()
        self._tpl = None

    def ops(self):
        from posixpath import abspath, dirname, join as pathjoin
        from io import BytesIO, StringIO

        def exists(p):
            return False

        def io_open(p, mode):
            return BytesIO() if 'b' in mode else StringIO()
        return abspath, dirname, pathjoin, exists, io_open

    def now(self):
        import datetime
        return datetime.datetime(2001, 1, 1)

    def FileSystemLoader(self, path):
        # kludge
        return self

    def load(self, env, tpl, context):
        self._tpl = tpl
        return self

    def render(self, context):
        return '... render %s with %s' % (self._tpl, context)


if __name__ == '__main__':
    def _script():
        '''Access to ambient authority derives
        from invocation as a script.
        '''
        from datetime import datetime
        from io import open as io_open
        from os import environ
        from os.path import abspath, dirname, join as pathjoin, exists
        from sys import stdin, stdout

        from jinja2 import FileSystemLoader

        cwd = Path('.', (abspath, dirname, pathjoin, exists, io_open))
        main(stdin, stdout, environ, cwd, datetime.now, FileSystemLoader)

    _script()
