# k8s-audit-collector

## Abstract
This project supports isolated advanced audit for multi tenants in kubernetes cluster.

## Motivation and Goals
Since kubernetes 1.7, kubernetes supports [advanced audit feature](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/). With the help of fluentd/logstash kubernetes cluster administrator can gather and distribute audit events to different users. The guidance introduced by kubernetes community can be found [here](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#log-collector-examples). Users will have access to their own audit events through a file or web page. However with such implementation, cluster administrator needs to configure extra authenticator to support tenant isolation. For example, administrator needs a file sharing service and distribution username/password to tenants. If administrator uses tools like Elasticsearch to implement access control, same issue still applies and administrator needs to maintain another authenticator along with kubernetes' own authenticator.

K8s-audit-collector provides a much more user-friendly way for users. It uses tenants' [serviceaccounts](https://kubernetes.io/docs/admin/service-accounts-admin/) to obtain the caller's identity and grants access permission to audit logs according to users' serviceaccounts.
Note: Serviceaccount token is designed to be presented to the apiserver in principle. Users should never send this token to any third party. If so, that third party may use this token to access the api-server as if it were the user. But here users should trust k8s-audit-collector because it is deployed and introduced by kubernetes administrator.

## Non-Goals
1. Search, analytics of audit events. Users should implement this themselves, if they want this feature.
2. RBAC authentication. K8s-audit-collector implements access control according to the namespace of serviceaccount. Access control of specific kubernetes role is not supported.


## Story about audit events
### 1.1 input
Now kubernetes advanced audit supports two kinds of backend: file and webhook. Currently k8s-audit-collector can read audit events from webhook backend.
### 1.2 collector
The collector deals with every audit event and figure out which namespace this audit event belongs to or it's a cluter scoped event.
### 1.3 output
Audit events from different namespaces are saved in different directories. And a rolling logger is used to write audit events to rolling files. Audit events are saved into different files while the amout of audit events grows larger. Old age audit events will be deleted if necessary.

## Story about http request from tenants
### 2.1 authentication
k8s-audit-collector validates serviceaccount token from tenants. Namespace and serviceaccount name are read from the serviceaccount token.
### 2.2 authorization
k8s-audit-collector allows tenants to read audits from their own namespace. Requests from specific namespace(like kube-system) can read all audit events.
### 2.3 read events
At this step, tenants will be able to read their own audit events saved in step [1.3](#13-output).

## deployment
1. k8s-audit-collector can both run inside a pod or run as a stand alone progress.
2. See [INSTALL.md](INSTALL.md) for details about how to deploy k8s-audit-collector

## alternatives
1. Use file shareing service(like nfs, ftp) to share the audit events to different users.
2. Use fluentd/elasticsearch and their authentication/authorization methods.
3. Save audit events to etcd storage and implement a feature like `kubectl get audits`.
