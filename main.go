package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/emicklei/go-restful"
	"github.com/golang/glog"
	"github.com/spf13/pflag"
)

const auditDir = "/var/log/audits/"

// Options contains the options passed to k8s audit collector
type Options struct {
	CertFile        string
	KeyFile         string
	ClientCAFile    string
	AuditsNum       uint
	SAKeyFiles      []string
	AdminNamespaces []string
	BindAddr        net.IP
	Port            uint
}

var options Options

func (o *Options) addFlags() {
	pflag.StringVar(&o.CertFile, "tls-cert-file", o.CertFile, ""+
		"File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated "+
		"after server cert).")
	pflag.StringVar(&o.KeyFile, "tls-private-key-file", o.KeyFile, ""+
		"File containing the default x509 private key matching --tls-cert-file.")
	pflag.StringVar(&o.ClientCAFile, "client-ca-file", o.ClientCAFile, ""+
		"A cert file for the client certificate authority")
	pflag.UintVar(&o.AuditsNum, "audits-number", 1000, ""+
		"Number of audit events saved in each log file.")
	pflag.StringSliceVar(&o.SAKeyFiles, "service-account-key-files", o.SAKeyFiles, "File containing PEM-encoded x509 RSA or ECDSA private or public keys, used to verify ServiceAccount tokens. Admin should pass just the same value with kube-apiserver")
	pflag.StringSliceVar(&o.AdminNamespaces, "admin-namespaces", []string{"kube-system"}, "Service accounts from which namespaces are treated as reqeust from administrator.")
	pflag.IPVar(&o.BindAddr, "bind-address", net.ParseIP("0.0.0.0"), "The IP address on which to listen for.")
	pflag.UintVar(&o.Port, "bind-port", 443, "The port on which to listen for.")
}

func main() {
	options.addFlags()
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	prepareWrite()
	prepareRead()

	cert, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	if err != nil {
		glog.Fatal(err)
		return
	}
	certBytes, err := ioutil.ReadFile(options.ClientCAFile)
	if err != nil {
		panic("Unable to read client certificate authority")
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		panic("failed to parse root certificate")
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// This allows certificates to be validated by authenticators, while still allowing other auth types
		// We support two kinds of authentication:
		// 1. certification for kube-apiserver audit webhook
		// 2. serviceaccount token for requests from pods
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  clientCertPool,
	}
	ws := new(restful.WebService)

	ws.Route(ws.POST("/write").Filter(authenWrite).To(writeHandler))

	ws.Route(ws.GET("/read/{ns}/{subpath:*}").Filter(authenRead).Filter(authorRead).To(readHandler))
	ws.Route(ws.GET("/read/{ns}/").Filter(authenRead).Filter(authorRead).To(readListHandler))
	ws.Route(ws.GET("/read/").Filter(authenRead).Filter(authorRead).To(readRootListHandler))

	restful.Add(ws)
	server := &http.Server{
		Addr:      fmt.Sprintf("%v:%d", options.BindAddr, options.Port),
		TLSConfig: config,
	}
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
