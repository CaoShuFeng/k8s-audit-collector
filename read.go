package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/emicklei/go-restful"
	"github.com/golang/glog"
	"gopkg.in/square/go-jose.v2/jwt"
	certutil "k8s.io/client-go/util/cert"
)

var publicKeys []interface{}

func prepareRead() {
	for _, keyFile := range options.SAKeyFiles {
		publicKey, err := certutil.PublicKeysFromFile(keyFile)
		if err != nil {
			panic(err)
		}
		publicKeys = append(publicKeys, publicKey...)
		glog.Info("Successfully loaded public key ", keyFile)
	}
}

type legacyPrivateClaims struct {
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName         string `json:"kubernetes.io/serviceaccount/secret.name"`
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
}

func (l legacyPrivateClaims) String() string {
	return fmt.Sprintf("ServiceAccount: %s, UID: %s, Secret: %s, Namespace: %s", l.ServiceAccountName, l.ServiceAccountUID, l.SecretName, l.Namespace)
}

// authenticateToken parses the jwt token
// this function is modified from:
// https://github.com/kubernetes/kubernetes/blob/ba791275ce5fa45a807820031b815055312f335d/pkg/serviceaccount/jwt.go#L139
func authenticateToken(token string) (*legacyPrivateClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := struct {
		// WARNING: this JWT is not verified. Do not trust these claims.
		Issuer string `json:"iss"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	// https://github.com/kubernetes/kubernetes/blob/ba791275ce5fa45a807820031b815055312f335d/pkg/serviceaccount/legacy.go#L37
	if claims.Issuer != "kubernetes/serviceaccount" {
		return nil, fmt.Errorf("invalid iss user provided")
	}
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	public := &jwt.Claims{}
	private := &legacyPrivateClaims{}
	var (
		found   bool
		errlist []error
	)
	for _, key := range publicKeys {
		if err := tok.Claims(key, public, private); err != nil {
			errlist = append(errlist, err)
			continue
		}
		found = true
		break
	}
	if found {
		return private, nil
	} else {
		result := fmt.Sprintf("[%s", errlist[0].Error())
		for i := 1; i < len(errlist); i++ {
			result += fmt.Sprintf(", %s", errlist[i].Error())
		}
		result += "]"
		glog.Infof("failed to check service account. errors: %s.", result)
		return nil, fmt.Errorf(result)
	}
}

// authenRead checks service account token
func authenRead(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	auth := strings.TrimSpace(req.Request.Header.Get("Authorization"))
	if len(auth) == 0 {
		resp.WriteErrorString(401, "Service account token is required.")
		return
	}
	parts := strings.Split(auth, " ")
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		resp.WriteErrorString(401, "Invalid token format")
		return
	}

	token := parts[1]
	// Empty bearer tokens aren't valid
	if len(token) == 0 {
		resp.WriteErrorString(401, "Service account token is required.")
		return
	}
	user, err := authenticateToken(token)
	if err != nil {
		resp.WriteErrorString(401, "Failed to validate service account token: "+err.Error())
		return
	}
	glog.Info("Successfully validated service account info: ", user)
	ctx := req.Request.Context()
	ctx = context.WithValue(ctx, "user", user)
	req.Request = req.Request.WithContext(ctx)
	chain.ProcessFilter(req, resp)
}

func authorRead(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	user, ok := req.Request.Context().Value("user").(*legacyPrivateClaims)
	if !ok || user == nil {
		resp.WriteErrorString(500, "Failed to read service account info")
		return
	}
	ns := req.PathParameter("ns")
	isAdmin := false
	if ns != user.Namespace {
		for _, adminNs := range options.AdminNamespaces {
			if user.Namespace == adminNs {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			scope := ""
			if len(ns) != 0 && ns != "{cluster-scope}" {
				scope = "in namespace '" + ns + "'"
			} else {
				scope = "in cluster scope"
			}
			resp.WriteErrorString(403, "Service account in namespaces '"+user.Namespace+"' are not allowed to access audits "+scope+".")
			return
		}
	}
	chain.ProcessFilter(req, resp)
}

// readHandler is the http handler for reqeust URL `read/{ns}/{subpath:*}`
func readHandler(req *restful.Request, resp *restful.Response) {
	actual := path.Join(auditDir, req.PathParameter("ns"), req.PathParameter("subpath"))
	glog.Infof("serving %s ... (from %s)\n", actual, req.Request.URL)
	http.ServeFile(
		resp.ResponseWriter,
		req.Request,
		actual)
}

// readListHandler is the http handler for reqeust URL `read/{ns}/`
func readListHandler(req *restful.Request, resp *restful.Response) {
	actual := path.Join(auditDir, req.PathParameter("ns"))
	glog.Infof("serving %s ... (from %s)\n", actual, req.Request.URL)
	http.ServeFile(
		resp.ResponseWriter,
		req.Request,
		actual)
}

// readRootListHandler is the http handler for reqeust URL `read/`
func readRootListHandler(req *restful.Request, resp *restful.Response) {
	glog.Infof("serving %s ... (from %s)\n", auditDir, req.Request.URL)
	http.ServeFile(
		resp.ResponseWriter,
		req.Request,
		auditDir)
}
