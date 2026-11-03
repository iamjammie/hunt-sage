---
title: "Playbook: Kubernetes & Container Hunting"
permalink: /hunt/playbooks/kubernetes-containers/
excerpt: "Hunt exec into pods, privileged and hostPath pods, service-account token abuse, cluster-admin bindings, rogue images and CronJobs in Kubernetes audit logs."
tactic: "Execution"
attack: [T1609, T1610, T1611, T1613, T1552.007, T1053.007, T1525, T1078.004]
difficulty: 3
timebox: "1-2 days"
data: [kubernetes-audit, edr, aws-cloudtrail]
---

{% include playbook-meta.html %}

**Data used:** Kubernetes API server audit log (AKS `AKSAudit` / `AzureDiagnostics` kube-audit, EKS control-plane logs in CloudWatch, GKE Cloud Audit Logs), container runtime / node EDR (Falco, Defender for Containers, Sysdig), cloud control-plane logs (CloudTrail for EKS and IAM roles), registry logs

## Background

A Kubernetes cluster is a distributed operating system with its own identity model, scheduler and secrets store, and the attacker's path through it is predictable: a foothold in one pod (exposed app, leaked kubeconfig, stolen cloud credential), then **the API server**. From there they enumerate what the service account can see, read secrets, run commands in other pods, schedule a privileged pod to break out to the node, bind themselves to `cluster-admin`, and leave a CronJob or a trojanised image behind.

Almost all of it is visible in the **API server audit log**, provided the audit policy records request bodies at `RequestResponse` level for the sensitive resources. Each record carries the actor (`user.username`, `user.groups`, impersonated user), the action (`verb`), the target (`objectRef.namespace`, `objectRef.resource`, `objectRef.subresource`, `objectRef.name`), the source (`sourceIPs`, `userAgent`) and the outcome (`responseStatus.code`). Runtime telemetry from the nodes adds what happened *inside* the container after `exec`.

Naming differs slightly per platform: AKS writes to `AKSAudit` (or `AzureDiagnostics` with `Category == "kube-audit"` on older workspaces), EKS to the CloudWatch log group `/aws/eks/<cluster>/cluster` (stream `kube-apiserver-audit`), GKE to Cloud Logging `k8s.io` audit logs. The field names below follow the upstream audit schema; adjust the table name.

## Hypothesis

> *If a cluster has been compromised, then we would see one identity (user, service account or node) perform an unusual sequence in the API audit log: enumerate resources across namespaces, read secrets in bulk, exec into pods, create a privileged or hostPath pod, grant itself cluster-admin, or schedule a CronJob, often from a source IP outside the CI/CD and admin ranges.*

## Data required

- An **audit policy** that logs at `Metadata` for everything and `RequestResponse` for `pods`, `pods/exec`, `pods/attach`, `secrets`, `configmaps`, `serviceaccounts`, `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`, `cronjobs`, `daemonsets` and `deployments`. Managed services: enable the `kube-audit` (AKS) / `audit` (EKS) / Admin and Data Access (GKE) log categories; the defaults often log only metadata.
- Audit log shipped to the SIEM with the `requestObject` and `responseObject` JSON preserved.
- Runtime detection on nodes (Falco rules or EDR with container awareness) for shells, package managers and mounts inside containers.
- An inventory of **legitimate automation identities** (CI/CD service accounts, GitOps controllers such as Argo CD or Flux, cluster autoscaler, monitoring agents) and admin source ranges; everything in this playbook is stacked against that list.
- Registry allow-list: which registries and namespaces may run `:latest` or public images.

```yaml
# Minimal audit policy fragment (kube-apiserver --audit-policy-file)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods", "pods/exec", "pods/attach", "pods/portforward", "secrets", "serviceaccounts", "serviceaccounts/token"]
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterrolebindings", "rolebindings", "clusterroles", "roles"]
      - group: "batch"
        resources: ["cronjobs", "jobs"]
      - group: "apps"
        resources: ["daemonsets", "deployments"]
  - level: Metadata
```

## Hunt steps

### 1. Anonymous and unauthenticated requests

```kql
AKSAudit
| where TimeGenerated > ago(7d)
| where User.username in ("system:anonymous", "system:unauthenticated") or User.groups has "system:unauthenticated"
| extend Code = toint(ResponseStatus.code)
| summarize Requests = count(), Allowed = countif(Code < 400), URIs = make_set(RequestUri, 10) by tostring(SourceIps), UserAgent
| order by Allowed desc, Requests desc
```

```spl
sourcetype="kube:apiserver-audit" (user.username="system:anonymous" OR user.groups{}="system:unauthenticated")
| stats count as requests count(eval('responseStatus.code'<400)) as allowed values(requestURI) as uris by sourceIPs{}, userAgent
| sort - allowed, - requests
```

Any **allowed** anonymous request other than `/healthz`, `/livez`, `/readyz` and `/version` means RBAC grants rights to `system:anonymous` or `system:unauthenticated`; that is a misconfiguration worth fixing immediately. Also check the kubelet: TCP 10250 reachable with `--anonymous-auth=true` lets an attacker list and exec into pods without ever touching the API server, so pull node firewall and VPC flow logs for 10250/10255 from non-control-plane addresses.

### 2. Exec, attach and port-forward into pods

```kql
AKSAudit
| where TimeGenerated > ago(14d) and Verb == "create"
| where ObjectRef.resource == "pods" and ObjectRef.subresource in ("exec", "attach", "portforward")
| extend Actor = tostring(User.username), Namespace = tostring(ObjectRef.namespace), Pod = tostring(ObjectRef.name)
| extend Command = extract(@"command=([^&]+)", 1, RequestUri)
| summarize Sessions = count(), Pods = dcount(Pod), Namespaces = dcount(Namespace), IPs = make_set(SourceIps, 5),
            Commands = make_set(Command, 10), First = min(TimeGenerated) by Actor, UserAgent
| order by Sessions desc
```

```spl
sourcetype="kube:apiserver-audit" verb=create objectRef.resource=pods objectRef.subresource IN (exec, attach, portforward)
| rex field=requestURI "command=(?<command>[^&]+)"
| stats count as sessions dc(objectRef.name) as pods dc(objectRef.namespace) as namespaces values(sourceIPs{}) as ips values(command) as commands min(_time) as first by user.username, userAgent
| sort - sessions
```

Stack by actor. Developers exec into their own namespace with `kubectl` from the office or VPN range; a **service account** execing into pods (`system:serviceaccount:<ns>:<name>`), exec from a pod IP, exec with `sh`/`bash`/`ash` into `kube-system`, or a `curl`/`python-requests`/`Go-http-client` user agent are the outliers. First-seen actor→namespace pairs over 30 days are a fast cut.

### 3. Privileged, hostPID, hostNetwork and hostPath pods

```kql
AKSAudit
| where TimeGenerated > ago(14d) and Verb in ("create", "update", "patch")
| where ObjectRef.resource in ("pods", "deployments", "daemonsets", "jobs", "cronjobs")
| extend Spec = tostring(RequestObject)
| where Spec has '"privileged":true' or Spec has '"hostPID":true' or Spec has '"hostNetwork":true' or Spec has '"hostIPC":true'
     or Spec has '"hostPath"' or Spec has '"SYS_ADMIN"' or Spec has '"SYS_PTRACE"' or Spec has '"SYS_MODULE"'
| extend Actor = tostring(User.username), Namespace = tostring(ObjectRef.namespace), Name = tostring(ObjectRef.name)
| extend Image = extract(@'"image":"([^"]+)"', 1, Spec), HostPath = extract(@'"hostPath":\{"path":"([^"]+)"', 1, Spec)
| project TimeGenerated, Actor, Namespace, Name, Image, HostPath, SourceIps, UserAgent
| order by TimeGenerated desc
```

```spl
sourcetype="kube:apiserver-audit" verb IN (create, update, patch) objectRef.resource IN (pods, deployments, daemonsets, jobs, cronjobs)
| spath input=requestObject
| search "requestObject.spec.containers{}.securityContext.privileged"=true OR "requestObject.spec.hostPID"=true OR "requestObject.spec.hostNetwork"=true OR "requestObject.spec.hostIPC"=true OR "requestObject.spec.volumes{}.hostPath.path"=* OR "requestObject.spec.containers{}.securityContext.capabilities.add{}" IN (SYS_ADMIN, SYS_PTRACE, SYS_MODULE)
| table _time, user.username, objectRef.namespace, objectRef.name, requestObject.spec.containers{}.image, requestObject.spec.volumes{}.hostPath.path, sourceIPs{}, userAgent
```

A `hostPath` of `/`, `/etc`, `/var/run/docker.sock`, `/run/containerd/containerd.sock` or `/proc` combined with `privileged` is a node takeover kit. Exclude the known DaemonSets (CNI, CSI drivers, log shippers, security agents) by name and namespace, then look at what is left: pods in user namespaces with `nodeName` pinned to a control-plane or high-value node, `tolerations` for every taint, and images such as `alpine`, `ubuntu`, `busybox` with a `sleep infinity` command.

### 4. Secrets access and service-account token abuse

```kql
AKSAudit
| where TimeGenerated > ago(7d)
| where ObjectRef.resource in ("secrets", "serviceaccounts") and Verb in ("get", "list", "watch", "create")
| extend Actor = tostring(User.username), Namespace = tostring(ObjectRef.namespace), Sub = tostring(ObjectRef.subresource)
| where Actor !startswith "system:node:" and Actor !in ("system:kube-controller-manager", "system:kube-scheduler")
| summarize Reads = count(), Namespaces = dcount(Namespace), Secrets = dcount(ObjectRef.name), Lists = countif(Verb == "list"),
            TokenRequests = countif(Sub == "token"), IPs = make_set(SourceIps, 5) by Actor, bin(TimeGenerated, 1h)
| where Reads >= 20 or Lists >= 3 or Namespaces >= 3 or TokenRequests >= 1
| order by Reads desc
```

```spl
sourcetype="kube:apiserver-audit" objectRef.resource IN (secrets, serviceaccounts) verb IN (get, list, watch, create) NOT user.username="system:node:*" NOT user.username IN ("system:kube-controller-manager","system:kube-scheduler")
| bin _time span=1h
| stats count as reads dc(objectRef.namespace) as namespaces dc(objectRef.name) as secrets count(eval(verb="list")) as lists count(eval('objectRef.subresource'="token")) as token_requests values(sourceIPs{}) as ips by user.username, _time
| where reads>=20 OR lists>=3 OR namespaces>=3 OR token_requests>=1
| sort - reads
```

Then pivot on **where the token is used from**: a service account whose pods run in namespace `payments` on nodes `10.1.x.x`, suddenly authenticating from an IP outside the cluster CIDR, or from a pod in another namespace, means the token was copied out of `/var/run/secrets/kubernetes.io/serviceaccount/token`. Compare `sourceIPs` per service account against the pod and node CIDRs, and look for `TokenRequest` (`serviceaccounts/token`) for high-privilege accounts by identities that never did so before.

### 5. RBAC escalation: cluster-admin and wildcard roles

```kql
AKSAudit
| where TimeGenerated > ago(30d) and Verb in ("create", "update", "patch")
| where ObjectRef.resource in ("clusterrolebindings", "rolebindings", "clusterroles", "roles")
| extend Body = tostring(RequestObject), Actor = tostring(User.username)
| where Body has '"name":"cluster-admin"' or Body has '"verbs":["*"]' or Body has '"resources":["*"]'
     or Body has "system:masters" or Body has "escalate" or Body has "impersonate" or Body has '"bind"'
| extend Subject = extract(@'"subjects":\[\{"kind":"([^"]+)","(?:apiGroup|namespace)?[^}]*"name":"([^"]+)"', 2, Body)
| project TimeGenerated, Actor, Verb, Resource = tostring(ObjectRef.resource), Name = tostring(ObjectRef.name), Subject, SourceIps
```

```spl
sourcetype="kube:apiserver-audit" verb IN (create, update, patch) objectRef.resource IN (clusterrolebindings, rolebindings, clusterroles, roles)
| spath input=requestObject
| search "requestObject.roleRef.name"=cluster-admin OR "requestObject.rules{}.verbs{}"="*" OR "requestObject.rules{}.resources{}"="*" OR "requestObject.subjects{}.name"="system:masters" OR "requestObject.rules{}.verbs{}" IN (escalate, impersonate, bind)
| table _time, user.username, verb, objectRef.resource, objectRef.name, requestObject.subjects{}.kind, requestObject.subjects{}.name, sourceIPs{}
```

Any new binding to `cluster-admin` outside a change window, a binding whose subject is a `ServiceAccount` in a workload namespace, or a role granting `pods/exec`, `secrets` or `*` to a default service account is an escalation. Also stack `impersonate` headers (`impersonatedUser` in the audit record): a non-admin identity acting as `system:masters` is a textbook privilege escalation.

### 6. Images from unknown registries and rogue workloads

```kql
let allowed = dynamic(["myregistry.azurecr.io", "123456789012.dkr.ecr.eu-west-1.amazonaws.com", "registry.k8s.io", "mcr.microsoft.com"]);
AKSAudit
| where TimeGenerated > ago(14d) and Verb == "create"
| where ObjectRef.resource in ("pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs")
| extend Images = extract_all(@'"image":"([^"]+)"', tostring(RequestObject))
| mv-expand Image = Images to typeof(string)
| extend Registry = iff(Image has "/", tostring(split(Image, "/")[0]), "docker.io")
| where not(Registry in~ (allowed)) or Image endswith ":latest" or Image !has ":" or Image has_any ("kali", "xmrig", "minerd")
| summarize Workloads = dcount(ObjectRef.name), Namespaces = make_set(ObjectRef.namespace, 5), Actors = make_set(User.username, 5), First = min(TimeGenerated) by Image, Registry
| order by First desc
```

```spl
sourcetype="kube:apiserver-audit" verb=create objectRef.resource IN (pods, deployments, daemonsets, statefulsets, jobs, cronjobs)
| spath input=requestObject output=image path="spec.containers{}.image"
| mvexpand image
| eval registry=if(match(image,"^[^/]+\\.[^/]+/"), mvindex(split(image,"/"),0), "docker.io")
| where NOT registry IN ("myregistry.azurecr.io","123456789012.dkr.ecr.eu-west-1.amazonaws.com","registry.k8s.io","mcr.microsoft.com") OR match(image,":latest$") OR match(image,"(?i)xmrig|minerd|kali")
| stats dc(objectRef.name) as workloads values(objectRef.namespace) as namespaces values(user.username) as actors min(_time) as first by image, registry
| sort first
```

First-seen images per namespace are the long tail to read. Cross-check against the registry: a tag that was **overwritten** (same tag, new digest) on a base image everyone inherits is the T1525 implant pattern; registry push logs and admission-controller (Kyverno, Gatekeeper, image-policy webhook) denials give you both sides.

### 7. CronJobs, DaemonSets and other persistence

```kql
AKSAudit
| where TimeGenerated > ago(30d) and Verb in ("create", "update", "patch")
| where ObjectRef.resource in ("cronjobs", "daemonsets") or (ObjectRef.resource == "pods" and tostring(RequestObject) has '"restartPolicy":"Always"' and tostring(ObjectRef.namespace) == "kube-system")
| extend Actor = tostring(User.username), Namespace = tostring(ObjectRef.namespace), Body = tostring(RequestObject)
| where Actor !has "argocd" and Actor !has "flux" and Actor !startswith "system:"
| extend Schedule = extract(@'"schedule":"([^"]+)"', 1, Body), Image = extract(@'"image":"([^"]+)"', 1, Body), Cmd = extract(@'"command":\[([^\]]+)\]', 1, Body)
| project TimeGenerated, Actor, Namespace, Resource = tostring(ObjectRef.resource), Name = tostring(ObjectRef.name), Schedule, Image, Cmd, SourceIps
```

```spl
sourcetype="kube:apiserver-audit" verb IN (create, update, patch) (objectRef.resource IN (cronjobs, daemonsets) OR (objectRef.resource=pods objectRef.namespace=kube-system)) NOT user.username="system:*" NOT user.username="*argocd*" NOT user.username="*flux*"
| spath input=requestObject
| table _time, user.username, objectRef.namespace, objectRef.resource, objectRef.name, requestObject.spec.schedule, requestObject.spec.jobTemplate.spec.template.spec.containers{}.image, requestObject.spec.jobTemplate.spec.template.spec.containers{}.command{}, sourceIPs{}
```

CronJobs created by a human or a workload service account rather than the GitOps controller, in `kube-system` or `default`, running `curl | sh`, `wget`, `nc`, `python -c` or a miner, are the ones to triage. Also list `ValidatingWebhookConfiguration` / `MutatingWebhookConfiguration` creations: a mutating webhook can inject a sidecar into every new pod.

### 8. Discovery bursts

```kql
AKSAudit
| where TimeGenerated > ago(7d) and Verb in ("list", "get", "watch")
| extend Actor = tostring(User.username)
| where Actor !startswith "system:" or Actor startswith "system:serviceaccount:"
| summarize Resources = dcount(ObjectRef.resource), Namespaces = dcount(ObjectRef.namespace), Requests = count(),
            Forbidden = countif(toint(ResponseStatus.code) == 403), Kinds = make_set(ObjectRef.resource, 15) by Actor, tostring(SourceIps), bin(TimeGenerated, 10m)
| where Resources >= 8 or Forbidden >= 10
| order by Resources desc
```

```spl
sourcetype="kube:apiserver-audit" verb IN (list, get, watch) (NOT user.username="system:*" OR user.username="system:serviceaccount:*")
| bin _time span=10m
| stats dc(objectRef.resource) as resources dc(objectRef.namespace) as namespaces count as requests count(eval('responseStatus.code'=403)) as forbidden values(objectRef.resource) as kinds by user.username, sourceIPs{}, _time
| where resources>=8 OR forbidden>=10
| sort - resources
```

Tools such as `kubectl auth can-i --list`, `kube-hunter`, `peirates` and `kubeletctl` produce a burst of `selfsubjectrulesreviews`, `selfsubjectaccessreviews` and lists across `secrets`, `pods`, `nodes`, `namespaces`, `serviceaccounts` in seconds, with many 403s. A service account doing this has been stolen or its pod has been compromised.

### 9. Runtime and cloud-side signals

Node or runtime telemetry closes the loop on what happened inside the container:

- Shell spawned in a container (`sh`, `bash`, `ash` with a TTY) by a process that is not the entrypoint; package managers (`apt`, `apk`, `yum`, `pip install`) at runtime; network tools (`nmap`, `masscan`, `nc`) appearing in images that should not have them.
- Escape primitives: `nsenter -t 1`, `mount` of `/dev/sd*` or a cgroup with `release_agent`, writes to `/proc/sysrq-trigger`, `/proc/sys/kernel/core_pattern`, `/etc/ld.so.preload` on the host, or access to the container runtime socket.
- **IMDS from a pod**: HTTP to `169.254.169.254` (or `fd00:ec2::254`) by workloads that have no reason to fetch cloud credentials; on EKS without IMDSv2 hop-limit 1 this hands out the node role.

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d) and RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName !in~ ("kubelet", "aws-node", "kube-proxy", "cloud-node-manager")
| summarize Requests = count(), Procs = make_set(InitiatingProcessFileName, 10) by DeviceName, InitiatingProcessAccountName
```

On the cloud side, hunt CloudTrail for `AssumeRoleWithWebIdentity` (IRSA) by service accounts from unexpected source IPs, `eks:DescribeCluster` / `eks:ListClusters` enumeration by new principals, `UpdateClusterConfig` turning public endpoint access on or audit logging off, and `CreateAccessEntry` / `aws-auth` ConfigMap edits granting IAM principals `system:masters`. The [Cloud & Identity playbook]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) has the AWS identity hunts that usually precede these.

## Triage

| Check | Interpretation |
|---|---|
| Actor type | Human user with `kubectl` from admin range = probably ops; `system:serviceaccount:*` doing exec, RBAC or secrets reads = token theft or compromised pod |
| Source IP vs. pod/node CIDRs | Service-account requests from outside the cluster network = token exfiltrated |
| User agent | `kubectl/v1.x` is normal; `curl`, `python-requests`, `Go-http-client`, `kube-hunter`, `peirates` are tooling |
| Namespace | `kube-system`, `kube-public`, security tooling namespaces and anything holding payment or customer data outrank dev namespaces |
| Pod spec | `privileged` + `hostPath /` + `hostPID` + minimal image + `sleep` = node takeover; a CSI/CNI DaemonSet with the same flags is expected |
| Image provenance | Known registry, pinned digest, signed = fine; `:latest` from docker.io into prod, or a tag whose digest changed yesterday = investigate |
| Sequence | discovery → secrets → exec → privileged pod → clusterrolebinding within an hour is an intrusion, not a busy admin |
| Response codes | Many 403s then 200s = the attacker found the right identity |

## Common false positives

- GitOps and CI/CD controllers (Argo CD, Flux, Jenkins agents, GitHub Actions runners) creating workloads and RBAC on every deploy
- Security and observability DaemonSets that legitimately run privileged with hostPath (Falco, Datadog, Fluent Bit, CSI drivers, CNI plugins)
- Developers execing into their own namespaces during incident troubleshooting; break-glass access during outages
- Cluster upgrades and operators (cert-manager, external-secrets) reading many secrets at start-up
- Autoscaler and node bootstrap processes calling IMDS
- `kubectl get all -A` run by a new platform engineer (a discovery burst from an admin range)

## Escalate when

A service-account identity is used from outside the cluster, any exec or privileged/hostPath pod appears in `kube-system` or a production namespace from an identity that is not the deployment controller, a `cluster-admin` binding is created outside change control, or a runtime alert shows an escape primitive. Containment: rotate the service-account token (delete the secret / restart the pod with bound tokens), revoke the IAM role session or kubeconfig, cordon and isolate the node, snapshot the pod filesystem and node memory before deleting anything, and review the registry for tampered tags.

## Validate and operationalise

- Emulate (lab cluster only): `Invoke-AtomicTest T1609` (kubectl exec), `T1610` (deploy privileged pod), `T1613` (kubectl enumeration), `T1552.007` (list secrets via API), `T1053.007` (create CronJob); or run [Stratus Red Team](https://github.com/DataDog/stratus-red-team) `k8s.*` techniques and [kube-hunter](https://github.com/aquasecurity/kube-hunter) against a kind/minikube cluster with audit logging enabled, then confirm every step above returns the activity.
- Detection: [Kubernetes Exec or Attach into Pod]({{ site.baseurl }}/research/sigma/T1609-kubernetes-exec-into-container.yml), [Privileged or Host-Namespace Pod Created]({{ site.baseurl }}/research/sigma/T1611-privileged-or-hostpath-pod-created.yml); add admission-policy denials (Kyverno / Gatekeeper / Pod Security Admission `restricted`) as a prevention-plus-telemetry layer.
- Hardening: Pod Security Admission `restricted` by default with explicit exceptions; no `automountServiceAccountToken` for workloads that do not call the API; bound, short-lived projected tokens; RBAC least privilege with no wildcards and no `pods/exec` for service accounts; private API endpoint and kubelet `--anonymous-auth=false` with `--authorization-mode=Webhook`; IMDSv2 with hop limit 1 (EKS) or workload identity instead of node roles; image signing and digest pinning with an admission controller; network policies that deny egress to the API server and IMDS from application namespaces; audit logs to a SIEM outside the cluster with a 90-day minimum retention.

See also: [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) for what the attacker does on the node once they escape, [Cloud & Identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) for the IAM and Entra side, [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) for secrets leaving the estate, and the [Linux logs & auditd cheat sheet]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/).

{% include playbook-footer.html %}
