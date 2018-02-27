# how to deploy k8s-audit-collector

## build binary
```shell
# make
```

## Mutual TLS Authentication between kube-apiserver and k8s-audit-collector
It's recommended to use mutual authentication between kube-apiserver webhook and k8s-audit-collector. K8s-audit-collector doesn't allow anonymous requests. To support mutual TLS authentication, k8s administrator could generate certificates manually. The following files are required:
1. `ca.crt`. `ca.crt` is the root certificate bundle to use to verify client certificates. In this example both kube-apiserver webhook and k8s-audit-collector use `ca.crt` to trust each other.
2. `kube-apiserver.cert`. File containing the default x509 Certificate for kube-apiserver webhook backend.
3. `kube-apiserver.key`. File containing the default x509 private key matching `kube-apiserver.cert`.
4. `k8s-audit-collector.cert`. File containing the default x509 Certificate for k8s-audit-collector.
5. `k8s-audit-collector.key`. File containing the default x509 private key matching `k8s-audit-collector.cert`.

See [this page](https://kubernetes.io/docs/concepts/cluster-administration/certificates/) for details about how to generate these certificates.
After all these files prepared, we start k8s-audit-collector with such options:
```shell
k8s-audit-collector --client-ca-file=ca.crt --tls-cert-file=k8s-audit-collector.cert --tls-private-key-file=k8s-audit-collector.key
```

The kubeconfig file passed to `kube-apiserver --audit-webhook-config-file` would look like this:
```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /path/to/ca.crt
    server: https://<ip>:443/write/
  name: k8s-audit-collector
contexts:
- context:
    cluster: k8s-audit-collector
    user: k8s-webhook
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: k8s-webhook
  user:
    client-certificate: /path/to/kube-apiserver.cert
    client-key: /path/to/kube-apiserver.key
```

## service account authentication for requests from tenants' pods
K8s-audit-collector allow tenants to read their own audit events. This requires service account key files to verify ServiceAccount tokens. K8s administrator should pass exactly the same arguments to `k8s-audit-collector --service-account-key-file` with `kube-apiserver --service-account-key-file`.

## privileged namespaces
Read requests from specific namespaces are treated as requests from cluster administrator. They can access all audit events from different namespaces or cluster-scoped audit events. Use --admin-namespaces to specify the admin namespace.
```shell
k8s-audit-collector --admin-namespaces=kube-system,kube-public
```

## check the saved audit events
After k8s-audit-collector started, k8s-audit-collector saves received audit events into directory /var/log/audits/. K8s administrator should make sure audit events are received and saved correctly at /var/log/audits/.

## access the audit events from inside the pod
Now tenants can read their audit events inside a pod like this:
```shell
$ token=`cat /run/secrets/kubernetes.io/serviceaccount/token`
$ # use -k to skip checking k8s-audit-collector cert
$ curl -v  -H "Authorization: Bearer $token" -k  https://<ip>:<port>/read/my-namespace/
$ # or use --cacert for secure SSL
$ curl -v  -H "Authorization: Bearer $token" --cacert /var/kube/ca.crt  https://<ip>:<port>/read/my-namespace/
```
