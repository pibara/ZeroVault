#!/usr/bin/python
import jinja2
import os
import Cookie
import cgi
import base64
import hmac
import hashlib
import datetime
#CHANGE THIS SALT WHEN INSTALLED ON YOUR PERSONAL SERVER!
serversalt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP"
print "Content-type: text/html"
path = os.path.dirname(os.path.abspath(__file__))
templateEnv = jinja2.Environment(
    autoescape=False,
    loader=jinja2.FileSystemLoader(os.path.join(path, 'templates')),
    trim_blocks=False)

def render_template(template_filename, context):
    global templateEnv
    return templateEnv.get_template(template_filename).render(context)

servername = None
if "SERVER_NAME" in os.environ:
    servername = os.environ["SERVER_NAME"]
    html = "<H2>OOPS</H2><b>YOU SHOULD NEVER</b> access ZeroVault over a <b>UNENCRYPTED</b> connection!<br>Please visit the <A HREF=\"https://" + servername + "/\">HTTPS site</A>!"
else:
    html ="<H2>OOPS</H2>Broken server setup. No SERVER_NAME set."
if "HTTPS" in os.environ:
  if "HTTP_COOKIE" in os.environ:
    print
    cookie = Cookie.SimpleCookie(os.environ["HTTP_COOKIE"])
    rumpelroot = cookie["rumpelroot"].value
    context = {
        'rumpelroot': rumpelroot
    }
    html = render_template('rumpeltree.html',context)
  else:
    form = cgi.FieldStorage()
    if "password" in form:
        rumpelroot = base64.b32encode(hmac.new(serversalt,
                        msg=form["password"].value,
                        digestmod=hashlib.sha256).digest()).strip("=") 
        cookie = Cookie.SimpleCookie()
        cookie["rumpelroot"] = rumpelroot
        cookie["rumpelroot"]["domain"] = "password.capibara.com"
        cookie["rumpelroot"]["path"] = "/"
        expiration = datetime.datetime.now() + datetime.timedelta(days=365*20) 
        cookie["rumpelroot"]["expires"] = expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST")
        print cookie.output()
        print
        context = {
          'rumpelroot': rumpelroot
        }
        html = render_template('rumpeltree.html',context)
    else:
        print
        context = {}
        html = render_template('passwordform.html',context)
else:
  print
print html
