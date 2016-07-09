SSL Sandwich
============
Listens on a port, and wraps a (notionally plaintext) connection in SSL (TLS
in real life, but TLSSandwich looked funny).  Does bidirectional authentication
on both ends.

The name came from a guy I know.

This program has not (yet) received heavy testing, though given its simplicity,
it should be safe to use in production environments after thorough testing.

TLS Certificates
----------------
See [http://www.bite-code.com/2015/06/25/tls-mutual-auth-in-golang/] for more
details about generating certs.

[Easy-RSA](https://github.com/OpenVPN/easy-rsa) is another good solution.

Usage
-----
```
Usage: sslsandwich [options] -caddr <address:port>

Accepts connections, authenticates clients, and proxies comms to the upstream
(connect) server, authenticating it as well.

Options:
  -caddr address
    	Connect address
  -ccert certificate
    	Connect certificate (default "ccert.pem")
  -ckey key
    	Connect key (default "ckey.pem")
  -cvcert certificate
    	Connect validation certificate (default "cvcert.pem")
  -laddr address
    	Listen address (default ":4333")
  -lcert certificate
    	Listen certificate (default "lcert.pem")
  -lkey key
    	Listen key (default "lkey.pem")
  -lvcert certificate(s)
    	Listen validation certificate(s) (default "lvcert.pem")
  -s	Silence logging except fatal errors
  -v	Verbose logging
```

Binaries
--------
Available upon request.  I can usually be found on Freenode with the nick
`MagisterQuis`.

Windows
-------
Should work.
