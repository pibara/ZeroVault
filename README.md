# ZeroVault
Storage and Vault-less web based password management for managing website passwords.

ZeroVault is meant as a simple medium security web based alternative for password vault solutions.
Most of ZeroVault will run inside of your web browser without any server interaction. 
The ZeroVault server does at no point gain access to your site passwords. Note that while ZeroVault
is designed to put zero trust in the server operations, the server does serve the HTML and JavaScript
part of ZeroVault and users are suggested to use CTRL-U to validate no sensitive data is indeed 
transfered to the server.

The ZeroVault system works with two passphrases:

* A Vault setup passphrase: this passphrase is used to generate a cookie with a root capability for deriving all passwords. Any browser that you wish to use ZeroVault from will need the same value for this cookie and thus will need to be initialized with the vault setup passphrase.
* A generator passphrase. This passphrase that is never sent to the server is combined with the root capability to create a site-class capability used to create passwords for sites of a specific class. You are suggested to use different generator passphrases for different classes of web sites.

Zerovault will create secure recreatable passwords from domain username combinations. If desired, ZeroValut can also be used to generate a unique username for a site.

You may install ZeroVault on your own HTTPS web server or use the one on https://password.capibara.com/ if you don't feel the need to run your own instance. If you decide to run your own instance, take the following steps:

* Clone ZeroVault
* Configure a (virtual) https server on your web server.
* Copy index.cgi,vault.jpg and the templates directory to our document root
* Create a 'revoked' directory one directory up from your document root and make this directory writable for the uuid your server runs under.
* Edit index.cgi so that your server uses a unique salt


