#!/usr/bin/python
'''

>>> environ=dict(HTTPS='1', REQUEST_METHOD='POST')
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

    if "HTTPS" not in environ:
        print >>stdout
        print >>stdout, err_unencrypted(environ.get('SERVERNAME'))
        return

    templates = (cwd / __file__).resolve().parent / 'templates'
    get_template = Environment(
        autoescape=False,
        loader=FileSystemLoader(str(templates)),
        trim_blocks=False).get_template

    form = cgi.FieldStorage(fp=stdin, environ=environ)
    if "HTTP_COOKIE" not in environ:
        if "password" not in form:
            print >>stdout
            context = {}
            html = get_template('passwordform.html').render(context)
        else:
            set_cookie, context = set_password(form["password"].value, now())
            print >>stdout, set_cookie
            print >>stdout
            html = get_template('rumpeltree.html').render(context)
    else:
        print >>stdout
        context = vault_context(environ["HTTP_COOKIE"],
                                cwd.resolve().parent / "revoked",
                                form.getfirst("revocationkey"))
        html = get_template('rumpeltree.html').render(context)
    print >>stdout, html


def set_password(password, t0):
    '''Build cookie header, template context for a new password.

    >>> header, ctx = set_password('sekret', MockIO().now())
    >>> header
    ... # doctest: +ELLIPSIS
    'Set-Cookie: rumpelroot=KEM...; Domain=pass...; expires=...2020...; Path=/'
    >>> ctx
    {'rumpelroot': 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA'}
    '''
    rumpelroot = base64.b32encode(hmac.new(
        serversalt,
        msg=password,
        digestmod=hashlib.sha256).digest()).strip("=")
    cookie = Cookie.SimpleCookie()
    cookie["rumpelroot"] = rumpelroot
    cookie["rumpelroot"]["domain"] = "password.capibara.com"
    cookie["rumpelroot"]["path"] = "/"
    expiration = t0 + timedelta(days=365 * 20)
    cookie["rumpelroot"]["expires"] = expiration.strftime(
        "%a, %d-%b-%Y %H:%M:%S PST")
    context = {
      'rumpelroot': rumpelroot
    }
    return cookie.output(), context


def vault_context(http_cookie, revocationdir, revocationkey):
    '''Recover root from cookie and handle revocation.

    Suppose our visitor has set a password:

    >>> io = MockIO()
    >>> http_cookie, _ctx = set_password('sekret', MockIO().now())

    Ordinary case:

    >>> vault_context(http_cookie, Path('/r', io.ops()), None)
    ... # doctest: +NORMALIZE_WHITESPACE
    {'revocationlist': [],
     'rumpelroot': 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA'}
    >>> io.existing.keys()
    []

    Incident response:

    >>> key = '12345678901234567890123456789012'
    >>> vault_context(http_cookie, Path('/r', io.ops()), key)
    ... # doctest: +NORMALIZE_WHITESPACE
    {'revocationlist': ['12345678901234567890123456789012'],
     'rumpelroot': 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA'}
    >>> io.existing.keys()
    ['/r/YUKL3QIGJ3HAGAPERA2NYK32M6QZYZI2IBRTNQTTVLMOKD7WX6DA.json']

    '''
    cookie = Cookie.SimpleCookie(http_cookie)
    rumpelroot = cookie["rumpelroot"].value
    rumpelsub = base64.b32encode(hmac.new(
        serversalt,
        rumpelroot,
        digestmod=hashlib.sha256).digest()).strip("=")
    revocationjsonfile = revocationdir / (rumpelsub + ".json")
    revocationlist = []
    if (revocationjsonfile.exists()):
        with revocationjsonfile.open(mode='rb') as data_file:
            revocationlist = json.load(data_file)
    if revocationkey is not None:
        if len(revocationkey) == 32:
            revocationlist.append(revocationkey)
            with revocationjsonfile.open(mode='wb') as outfile:
                json.dump(revocationlist, outfile)
    context = {
        'rumpelroot': rumpelroot,
        'revocationlist': revocationlist
    }
    return context


def err_unencrypted(servername):
    if servername:
        html = ("<H2>OOPS</H2><b>YOU SHOULD NEVER</b> access ZeroVault "
                "over a <b>UNENCRYPTED</b> connection!<br>"
                "Please visit the <A HREF=\"https://" +
                servername + "/\">HTTPS site</A>!")
    else:
        html = "<H2>OOPS</H2>Broken server setup. No SERVER_NAME set."
    return html


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
        self.existing = {}
        self._tpl = None

    def ops(self):
        from posixpath import abspath, dirname, join as pathjoin
        from io import BytesIO, StringIO

        def exists(p):
            return p in self.existing

        def io_open(p, mode):
            if 'w' in mode:
                self.existing[p] = True
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
