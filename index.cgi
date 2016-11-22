#!/usr/bin/python
import jinja2
import os
import Cookie
import cgi
import base64
import hmac
import hashlib
import datetime
import json
#CHANGE THIS SALT WHEN INSTALLED ON YOUR PERSONAL SERVER!
serversalt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP"

path = os.path.dirname(os.path.abspath(__file__))
templateEnv = jinja2.Environment(
    autoescape=False,
    loader=jinja2.FileSystemLoader(os.path.join(path, 'templates')),
    trim_blocks=False)


def main(stdout):
    print >>stdout, "Content-type: text/html"

    servername = None
    if "SERVER_NAME" in os.environ:
        servername = os.environ["SERVER_NAME"]
        html = "<H2>OOPS</H2><b>YOU SHOULD NEVER</b> access ZeroVault over a <b>UNENCRYPTED</b> connection!<br>Please visit the <A HREF=\"https://" + servername + "/\">HTTPS site</A>!"
    else:
        html ="<H2>OOPS</H2>Broken server setup. No SERVER_NAME set."
    if "HTTPS" in os.environ:
      if "HTTP_COOKIE" in os.environ:
        print >>stdout
        cookie = Cookie.SimpleCookie(os.environ["HTTP_COOKIE"])
        rumpelroot = cookie["rumpelroot"].value
        rumpelsub = base64.b32encode(hmac.new(serversalt,
                            rumpelroot,
                            digestmod=hashlib.sha256).digest()).strip("=") 
        revocationjsonfile = "../revoked/" + rumpelsub + ".json"
        revocationlist = []
        if (os.path.exists(revocationjsonfile)):
            with open(revocationjsonfile) as data_file:    
                revocationlist = json.load(data_file)
        form = cgi.FieldStorage()
        revocekey = "NONE"
        if "revocationkey" in form:
           revocekey = form["revocationkey"].value
           if len(revocekey) == 32  :
               revocationlist.append(revocekey)
               with open(revocationjsonfile, 'w') as outfile:
                   json.dump(revocationlist, outfile)       
        context = {
            'rumpelroot': rumpelroot,
            'revocationlist': revocationlist
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
            print >>stdout, cookie.output()
            print >>stdout
            context = {
              'rumpelroot': rumpelroot
            }
            html = render_template('rumpeltree.html',context)
        else:
            print >>stdout
            context = {}
            html = render_template('passwordform.html',context)
    else:
      print >>stdout
    print >>stdout, html


def render_template(template_filename, context):
    global templateEnv
    return templateEnv.get_template(template_filename).render(context)


if __name__ == '__main__':
    def _script():
        from sys import stdout

        main(stdout)

    _script()
