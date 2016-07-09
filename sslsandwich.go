package main

/*
 * sslsandwich.go
 * Program to wrap a connection in SSL (well, TLS)
 * By J. Stuart McMurray
 * Created 20160709
 * Last Modified 20160709
 */

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

/* Logging functions */
var (
	verbose = func(string, ...interface{}) {}
	logit   = log.Printf
)

func main() {
	var (
		/* Listen side */
		laddr = flag.String(
			"laddr",
			":4333",
			"Listen `address`",
		)
		lcert = flag.String(
			"lcert",
			"lcert.pem",
			"Listen `certificate`",
		)
		lkey = flag.String(
			"lkey",
			"lkey.pem",
			"Listen `key`",
		)
		lvcert = flag.String(
			"lvcert",
			"lvcert.pem",
			"Listen validation `certificate(s)`",
		)
		/* Connect side */
		caddr = flag.String(
			"caddr",
			"",
			"Connect `address`",
		)
		ccert = flag.String(
			"ccert",
			"ccert.pem",
			"Connect `certificate`",
		)
		ckey = flag.String(
			"ckey",
			"ckey.pem",
			"Connect `key`",
		)
		cvcert = flag.String(
			"cvcert",
			"cvcert.pem",
			"Connect validation `certificate`",
		)
		/* Logging */
		silence = flag.Bool(
			"s",
			false,
			"Silence logging except fatal errors",
		)
		verbOn = flag.Bool(
			"v",
			false,
			"Verbose logging",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options] -caddr <address:port>

Accepts connections, authenticates clients, and proxies comms to the upstream
(connect) server, authenticating it as well.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Set logging options */
	if *silence && *verbOn {
		log.Fatalf("Cannot be silent (-s) and verbose (-v)!")
	}
	if *silence {
		logit = verbose
	} else if *verbOn {
		verbose = log.Printf
	}
	logit("logit")
	verbose("verbose")

	/* Make the config for the TLS connection to the target */
	conf := tlsConfig(*ccert, *ckey, *cvcert, true)

	/* Load TLS certificates to validate clients and target */
	l := listenTLS(*laddr, *lcert, *lkey, *lvcert)
	logit("Listening on %v", l.Addr())
	verbose("Will connect to %v", *caddr)

	/* Accept clients */
	for {
		c, err := l.Accept()
		logit("%v New connection", c.RemoteAddr())
		if nil != err {
			log.Fatalf(
				"Unable to accept clients on %v: %v",
				l.Addr(),
				err,
			)
		}
		go handle(*caddr, c, conf)
	}
}

/* listenTLS loads the cert and key, listens for tls connections on a.  Clients
are authenticated against the cert(s) in acert. */
func listenTLS(addr, cert, key, acert string) net.Listener {

	/* Make a TLS config */
	conf := tlsConfig(cert, key, acert, false)
	conf.ClientAuth = tls.RequireAndVerifyClientCert

	/* Listen on the Address */
	l, err := tls.Listen("tcp", addr, conf)
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", addr, err)
	}
	return l
}

/* tlsConfig makes a configuration from the cert and key.  The certificate(s)
in acert will be loaded and returned to be set in either the config's RootCAs
field or ClientCAs field, depending on whether the config is meant to be
used as a client.. */
func tlsConfig(cert, key, acert string, client bool) *tls.Config {
	/* Load server certificate */
	scert, err := tls.LoadX509KeyPair(cert, key)
	if nil != err {
		log.Fatalf(
			"Unable to load keypair from %v and %v: %v",
			cert, key,
			err,
		)
	}

	/* Load validation certificates */
	caCert, err := ioutil.ReadFile(acert)
	if err != nil {
		log.Fatalf(
			"Unable to open validation certificate(s) file %v: %v",
			acert,
			err,
		)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	/* Set up the TLS config */
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{scert},
	}
	if client {
		tlsConfig.RootCAs = caCertPool
	} else {
		tlsConfig.ClientCAs = caCertPool
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}

/* handle does the heavy lifting proxying comms between c and caddr. */
func handle(caddr string, c net.Conn, conf *tls.Config) {
	defer c.Close()
	/* Connect upstream */
	t, err := tls.Dial("tcp", caddr, conf)
	if nil != err {
		logit("%v Error connecting: %v", c.RemoteAddr(), err)
		return
	}
	verbose("%v Connected to %v", c.RemoteAddr(), t.RemoteAddr())

	/* Perform the copy */
	ch := make(chan iostat)
	go iocopy(c, t, "server -> client", ch)
	go iocopy(t, c, "client -> server", ch)
	/* Wait for the copy to finish */
	for i := 0; i < 2; i++ {
		st := <-ch
		/* Log it if we're meant to */
		if nil != st.err {
			verbose(
				"%v Error %v after %v bytes: %v",
				c.RemoteAddr(),
				st.dir,
				st.n,
				st.err,
			)
			continue
		}
		verbose(
			"%v Finished %v after %v bytes",
			c.RemoteAddr(),
			st.dir,
			st.n,
		)
	}
	logit("%v Finished.", c.RemoteAddr())
}

/* iostat holds the results of an io.Copy */
type iostat struct {
	n   int64
	err error
	dir string
}

/* iocopy copies bytes from src to dst, and when finished sends the values
returned from io.Copy as well as dir on ch */
func iocopy(dst io.Writer, src io.Reader, dir string, ch chan<- iostat) {
	/* Actually perform the copy */
	n, err := io.Copy(dst, src)
	ch <- iostat{
		n:   n,
		err: err,
		dir: dir,
	}
}
