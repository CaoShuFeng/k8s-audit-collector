// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/emicklei/go-restful"
	"github.com/golang/glog"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/client-go/util/jsonpath"
)

var (
	// jsonpath to parse an event
	jp *jsonpath.JSONPath

	// backends saves a backend for each namespace
	backends    map[string]*backend = make(map[string]*backend)
	backendLock sync.Mutex

	// we require certificates to be valid for client auth (x509.ExtKeyUsageClientAuth)
	opts x509.VerifyOptions
)

// backend is the audit writer for a namespace
type backend struct {
	logger *lumberjack.Logger
	index  uint32
}

// Write implements io.Writer
func (b *backend) Write(p []byte) (n int, err error) {
	index := atomic.AddUint32(&(b.index), 1)
	if index == uint32(options.AuditsNum+1) {
		b.logger.Rotate()
		atomic.AddUint32(&(b.index), ^uint32(options.AuditsNum-1))
	}
	return b.logger.Write(p)
}

// getBackend returns the audit writer for a namespace
func getBackend(namespace string) io.Writer {
	if len(namespace) == 0 {
		// {cluster-scope} is a illegal namespace name, so it never conficts with a real namespace
		namespace = "{cluster-scope}"
	}
	logger := backends[namespace]
	if logger == nil {
		backendLock.Lock()
		logger = backends[namespace]
		if logger == nil {
			backends[namespace] = &backend{
				logger: &lumberjack.Logger{
					MaxAge:   10,
					Filename: auditDir + namespace + "/audit",
				},
				index: 0,
			}
		}
		backendLock.Unlock()
		logger = backends[namespace]
	}
	return logger
}

func prepareWrite() error {
	// jsonpath
	jp = jsonpath.New("audit")
	jp.AllowMissingKeys(true)
	if err := jp.Parse("{$.objectRef.namespace}"); err != nil {
		return err
	}

	// x509 verify options
	certBytes, err := ioutil.ReadFile(options.ClientCAFile)
	if err != nil {
		return err
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return fmt.Errorf("failed to parse root certificate")
	}
	opts = x509.VerifyOptions{
		Roots:     clientCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return nil
}

// SaveEventList parse Advanced audit EventList json bytes.
// The EventList has such format:
// https://github.com/kubernetes/kubernetes/blob/3d4eaf73070b2acf3fb9d2a713a6164142b81257/staging/src/k8s.io/apiserver/pkg/apis/audit/v1beta1/types.go#L136
// SaveEventList handles each item of Event from EventList.
// The Event item has such format:
// https://github.com/kubernetes/kubernetes/blob/3d4eaf73070b2acf3fb9d2a713a6164142b81257/staging/src/k8s.io/apiserver/pkg/apis/audit/v1beta1/types.go#L72
// Events' objectRef.namespace is queried by jsonpath to determine which namspace this event belongs to.
func SaveEventList(eventBytes []byte) {
	var eventListInterface interface{}
	err := json.Unmarshal(eventBytes, &eventListInterface)
	if err != nil {
		glog.Warning(err)
		return
	}
	eventList, ok := eventListInterface.(map[string]interface{})
	if !ok {
		glog.Warningf("Can't convert to eventList： %s", eventBytes)
		return
	}
	items, ok := eventList["items"].([]interface{})
	if !ok {
		glog.Warningf("Can't convert to items： %s", eventBytes)
		return
	}
	for _, item := range items {
		buf := new(bytes.Buffer)
		err = jp.Execute(buf, item)
		if err != nil {
			glog.Warningf("failed to parse json %v", err)
			continue
		}
		bytes, err := json.Marshal(item)
		if err != nil {
			glog.Warningf("failed to marshal to json %v", err)
			continue
		}
		saveEvent(buf.String(), bytes)
	}
}

// saveEvent saves a event to its backend file according to its namespace.
// If namespace is empty string, then it's a cluster scope request.
func saveEvent(namespace string, event []byte) {
	writer := getBackend(namespace)
	writer.Write(append(event, '\n'))
}

// authenWrite verifies the PeerCertificates
func authenWrite(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if req.Request.TLS == nil || len(req.Request.TLS.PeerCertificates) == 0 {
		resp.WriteErrorString(401, "401: Not Authorized")
		return
	}
	if _, err := req.Request.TLS.PeerCertificates[0].Verify(opts); err != nil {
		resp.WriteErrorString(401, "Not Authorized. "+err.Error())
		return
	}
	glog.V(5).Info(req.Request.TLS.PeerCertificates[0].Subject.CommonName, " authenticated.")
	chain.ProcessFilter(req, resp)
}

// writeHandler is the http handler for reqeust URL `write`
func writeHandler(req *restful.Request, resp *restful.Response) {
	b, err := ioutil.ReadAll(req.Request.Body)
	if err != nil {
		glog.Warning(err)
	}
	SaveEventList(b)
	resp.WriteHeader(http.StatusOK)
}
