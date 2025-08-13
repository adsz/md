# 🎯 Senior DevOps Interview Q&A - Advanced Kubernetes

> **An advanced guide to platform-agnostic Kubernetes concepts. This covers the deep architectural and operational knowledge required for Senior DevOps, SRE, and Platform Engineering roles in any K8s environment.**

---

## ⚙️ **Control Plane & Core Concepts**

### ❓ Q1: Describe the main components of the Kubernetes Control Plane and their functions.
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
The Control Plane is the "brain" of the cluster. Its main components are:
-   **API Server (`kube-apiserver`)**: The front door. All communication to and from the control plane goes through it.
-   **etcd**: The database. A consistent and highly-available key-value store for all cluster data (the desired state).
-   **Scheduler (`kube-scheduler`)**: The matchmaker. It decides which node is best for a new pod to run on.
-   **Controller Manager (`kube-controller-manager`)**: The reconciler. It runs controllers that watch the cluster's state and work to make the actual state match the desired state (e.g., Node Controller, ReplicaSet Controller).

---

#### 🧠 **Theoretical Explanation**
These components work together in a continuous loop:
1.  A user sends a request to the **API Server** (e.g., `kubectl apply -f deployment.yaml`).
2.  The API Server validates the request and writes the desired state to **etcd**.
3.  The **Controller Manager** sees the new Deployment object and creates a corresponding ReplicaSet.
4.  The ReplicaSet controller sees it needs to create pods.
5.  The **Scheduler** sees the new, unscheduled pods. It analyzes the cluster nodes (resource availability, constraints, affinity rules) and assigns each pod to a node.
6.  The API Server writes this binding information to **etcd**.
7.  The `kubelet` on the assigned node sees the pod is bound to it and starts the container.

This entire process is a series of **reconciliation loops**, which is the core principle of Kubernetes.

</details>

### ❓ Q2: ⚠️ Tricky Question: What is `etcd` and why is it so critical? How would you back it up and restore it in a self-managed cluster?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
`etcd` is the distributed key-value store that holds the entire state of the Kubernetes cluster. It is the single source of truth. If you lose the `etcd` data, you lose your cluster's state—all Deployments, Services, ConfigMaps, etc., are gone.

**Backup**: You back it up by using the `etcdctl snapshot save` command.
**Restore**: You restore by stopping the API server, running `etcdctl snapshot restore`, and then reconfiguring the `etcd` service to point to the new data directory.

---

#### 🧠 **Detailed Backup & Restore Process**
This must be done on a control plane node where `etcdctl` is installed and has access to the `etcd` certificates.

**1. Backup**
```bash
# Set the API version for etcdctl
export ETCDCTL_API=3

# Take a snapshot
ETCD_ENDPOINT="127.0.0.1:2379"
ETCD_CACERT="/etc/kubernetes/pki/etcd/ca.crt"
ETCD_CERT="/etc/kubernetes/pki/etcd/server.crt"
ETCD_KEY="/etc/kubernetes/pki/etcd/server.key"

etcdctl snapshot save /var/lib/etcd-backups/snapshot.db \
  --endpoints=$ETCD_ENDPOINT \
  --cacert=$ETCD_CACERT \
  --cert=$ETCD_CERT \
  --key=$ETCD_KEY
```
This snapshot file should then be copied to a secure, external location (like S3).

**2. Restore**
This is a critical, cluster-down operation.
1.  Stop the `kube-apiserver` and the `etcd` service on all control plane nodes.
2.  Run the restore command:
    ```bash
    etcdctl snapshot restore /var/lib/etcd-backups/snapshot.db \
      --data-dir /var/lib/etcd-new
    ```
3.  Update the `etcd.yaml` static pod manifest (in `/etc/kubernetes/manifests/`) to change the `hostPath` for its data volume to point to the new directory (`/var/lib/etcd-new`).
4.  Restart the `kubelet` to apply the manifest changes. This will restart the `etcd` pod with the restored data.
5.  Restart the `kube-apiserver`

</details>

### ❓ Q3: What is the Operator Pattern?
<details>
<summary>Click to see the answer</summary>

The Operator Pattern is a way to extend Kubernetes with custom, application-specific logic. An Operator is a custom controller that you write to manage a complex, stateful application.

It combines:
1.  **Custom Resource Definitions (CRDs)**: You define your own Kubernetes object, like `kind: PostgresqlDatabase`.
2.  **A Custom Controller**: A process running in the cluster that watches for these custom resources and takes action to make the actual state match the desired state defined in the resource.

**Example**: A PostgreSQL Operator. A developer can create a simple YAML file: `apiVersion: db.my.org/v1, kind: PostgresqlDatabase, metadata: {name: my-db}, spec: {version: "14", replicas: 3}`. The Operator sees this, and then performs all the complex actions needed: creates a StatefulSet, sets up PVCs, configures primary/replica replication, creates services, and manages backups. It encapsulates the domain knowledge of a database administrator into software.

</details>

### ❓ Q4: What is a reconciliation loop?
<details>
<summary>Click to see the answer</summary>

A reconciliation loop is the fundamental control loop at the heart of Kubernetes. Every controller in Kubernetes runs a loop with this logic:
1.  **Observe**: Get the current state of the system.
2.  **Diff**: Compare the current state to the desired state (stored in `etcd`).
3.  **Act**: Take actions to make the current state match the desired state.

**Example (ReplicaSet Controller)**:
-   **Desired State**: A ReplicaSet object exists that says "I want 3 pods with label `app=nginx`."
-   **Observe**: The controller lists all pods with that label and finds only 2 are running.
-   **Diff**: Current (2) != Desired (3).
-   **Act**: The controller calls the API server to create one more `nginx` pod.

This loop runs continuously, which is why Kubernetes is so resilient and self-healing.

</details>

### ❓ Q5: What is the difference between a static pod and a DaemonSet?
<details>
<summary>Click to see the answer</summary>

- **Static Pod**: A pod that is managed directly by the `kubelet` daemon on a specific node. There is no ReplicaSet or Deployment object for it in the API server. The `kubelet` watches for YAML files in a specific directory (e.g., `/etc/kubernetes/manifests`). They are used to run the control plane components themselves (like the API server and scheduler) on control plane nodes.
- **DaemonSet**: A Kubernetes object that ensures a copy of a pod runs on **all (or some) nodes** in the cluster. If a node is added, the DaemonSet controller automatically creates the pod on it. If a node is removed, the pod is garbage collected. It's used for cluster-wide agents like logging collectors (Fluent Bit), monitoring agents (Prometheus Node Exporter), or CNI plugins (Calico).

</details>

---

## 🚀 **Advanced Scheduling**

### ❓ Q6: What are Taints and Tolerations, and what is a common use case?
<details>
<summary>Click to see the answer</summary>

- **Taints**: Are applied to **nodes**. A taint marks a node so that no pods will be scheduled on it unless they have a matching toleration.
- **Tolerations**: Are applied to **pods**. A toleration allows a pod to be scheduled on a node with a matching taint.

**Use Case: Dedicated Nodes**
1.  You have a set of nodes with powerful GPUs that should only be used for machine learning workloads.
2.  You apply a **taint** to these nodes: `kubectl taint nodes gpu-node-1 key=gpu:NoSchedule`.
3.  Now, no normal pods can be scheduled there.
4.  You add a **toleration** to your ML pods' YAML, allowing them to be scheduled on the tainted nodes:
    ```yaml
    tolerations:
    - key: "gpu"
      operator: "Exists"
      effect: "NoSchedule"
    ```

</details>

### ❓ Q7: Explain Node Affinity, Pod Affinity, and Pod Anti-Affinity.
<details>
<summary>Click to see the answer</summary>

These are all rules you define in a pod's spec to influence the scheduler's placement decisions.

- **Node Affinity**: Attracts a pod to a **set of nodes**. It's like `nodeSelector` but more expressive.
    - **Use Case**: "Schedule this pod only on nodes that have SSDs and are in the `us-east-1a` availability zone."
- **Pod Affinity**: Attracts a pod to other **pods**. It schedules pods on the same node (or in the same topology domain) as other pods that match a certain label.
    - **Use Case**: "Schedule my web server pod on the same node as my Redis cache pod to reduce network latency."
- **Pod Anti-Affinity**: Repels a pod from other **pods**. It prevents pods with matching labels from being scheduled on the same node.
    - **Use Case**: "For high availability, never schedule two replicas of my database pod on the same physical node."

</details>

### ❓ Q8: What is the difference between `requiredDuringSchedulingIgnoredDuringExecution` and `preferredDuringSchedulingIgnoredDuringExecution`?
<details>
<summary>Click to see the answer</summary>

These are the two types of Node and Pod Affinity rules.
- **`required...`**: The rule **must** be met for the pod to be scheduled. If the scheduler cannot find any node that satisfies the rule, the pod will remain pending forever. It's a hard requirement.
- **`preferred...`**: The scheduler will **try** to find a node that meets the rule, but if it can't, it will schedule the pod on any available node. It's a soft requirement or a hint.

**`...IgnoredDuringExecution`**: This part means that if the node's labels change *after* the pod has been scheduled, Kubernetes will not evict the pod. The affinity rules only apply at scheduling time.

</details>

### ❓ Q9: How can you oversubscribe a cluster's resources safely?
<details>
<summary>Click to see the answer</summary>

Oversubscription means scheduling pods with resource `limits` that are higher than their `requests`, allowing the total `limits` on a node to exceed the node's actual capacity. This relies on the assumption that not all applications will use their full limit at the same time.

This is managed through **Quality of Service (QoS) Classes**:
1.  **Guaranteed**: Pods where `requests` equal `limits` for both CPU and memory. These are the highest priority pods and are the last to be killed if the node runs out of resources.
2.  **Burstable**: Pods where `requests` are lower than `limits`. These pods can "burst" and use more resources up to their limit if they are available on the node.
3.  **BestEffort**: Pods with no `requests` or `limits` set. These are the lowest priority and are the first to be killed during resource pressure.

**Safe Strategy**: Run critical, stateful applications as `Guaranteed`. Run standard web applications as `Burstable`. Run non-critical batch jobs as `BestEffort`.

</details>

### ❓ Q10: What is a Pod Disruption Budget (PDB)?
<details>
<summary>Click to see the answer</summary>

A PDB is a Kubernetes object that limits the number of pods of a replicated application that are simultaneously down from **voluntary disruptions** (like a node drain for an upgrade or a deployment rollout).

It does **not** protect against involuntary disruptions (like a hardware failure).

**Example**: You create a PDB for your `frontend` deployment that says `minAvailable: 3`. This tells Kubernetes, "At all times, I must have at least 3 pods for this application running." When you perform a `kubectl drain` on a node, Kubernetes will respect this PDB. It will evict pods one by one and wait for them to be rescheduled and become ready on another node before proceeding, ensuring your availability target is never breached.

</details>

---

## 🌐 **Networking**

### ❓ Q11: What is the difference between a Service's `ClusterIP`, `NodePort`, and `LoadBalancer` types?
<details>
<summary>Click to see the answer</summary>

- **`ClusterIP` (Default)**: Exposes the Service on an internal, cluster-only IP address. It is only reachable from within the cluster. This is used for internal service-to-service communication.
- **`NodePort`**: Exposes the Service on a static port on each worker node's IP address. A client can connect to `<NodeIP>:<NodePort>`. This is mainly used for development or when you need to expose a service without a cloud load balancer.
- **`LoadBalancer`**: Exposes the Service externally using a cloud provider's load balancer (e.g., an AWS NLB or ALB). The cloud provider automatically creates the load balancer and routes traffic to the service's NodePort. This is the standard way to expose services to the internet.

</details>

### ❓ Q12: How does DNS service discovery work in Kubernetes?
<details>
<summary>Click to see the answer</summary>

Kubernetes provides a built-in DNS service (usually CoreDNS).
1.  When you create a `Service` named `my-svc` in the `my-ns` namespace, the DNS service automatically creates a DNS record for it.
2.  A pod in the same namespace (`my-ns`) can simply connect to the service using its name: `http://my-svc`.
3.  A pod in a different namespace needs to use the fully qualified domain name (FQDN): `http://my-svc.my-ns.svc.cluster.local`.
4.  The `kubelet` configures each pod's `/etc/resolv.conf` to use the in-cluster DNS server and to search the local namespace first, which is why the short name works within the same namespace.

</details>

### ❓ Q13: What is the Kubernetes Gateway API?
<details>
<summary>Click to see the answer</summary>

The Gateway API is the next-generation, more expressive, and role-oriented successor to the Ingress API for managing traffic into the cluster.

It splits the responsibility into three roles:
1.  **GatewayClass**: Defined by the **Infrastructure Provider** (e.g., AWS, Google). It's a template for a load balancer.
2.  **Gateway**: Deployed by the **Cluster Operator**. It requests a load balancer based on a GatewayClass and defines the ports and protocols to listen on.
3.  **HTTPRoute**: Deployed by the **Application Developer**. It attaches to a Gateway and defines how to route traffic for a specific hostname or path to a backend Service.

This separation of concerns is much better suited for multi-tenant, enterprise environments than the monolithic Ingress object.

</details>

### ❓ Q14: What is eBPF and how is it changing Kubernetes networking?
<details>
<summary>Click to see the answer</summary>

**eBPF (extended Berkeley Packet Filter)** is a revolutionary Linux kernel technology that allows you to run sandboxed programs directly in the kernel without changing the kernel source code.

**Impact on Kubernetes Networking**:
-   CNI plugins like **Cilium** are built on eBPF.
-   They can provide networking, observability, and security with much higher performance than traditional `iptables`-based methods.
-   Because eBPF operates in the kernel, it can bypass `kube-proxy` and `iptables` entirely, leading to faster service routing and lower latency.
-   It enables very efficient implementation of Network Policies and provides deep, kernel-level visibility into network traffic.

</details>

### ❓ Q15: What is a CNI plugin's responsibility?
<details>
<summary>Click to see the answer</summary>

A CNI (Container Network Interface) plugin is responsible for the networking of containers. When `kubelet` starts a pod, it calls the configured CNI plugin with two main commands:
1.  **`ADD`**: Called when a pod is created. The CNI plugin is responsible for:
    *   Creating a network interface for the pod (e.g., a `veth` pair).
    *   Placing one end of the interface inside the pod's network namespace.
    *   Assigning an IP address to the pod's interface.
    *   Setting up the necessary routes so the pod can communicate with other pods.
2.  **`DEL`**: Called when a pod is deleted. The CNI plugin is responsible for cleaning up all the network resources it created for that pod.

</details>

---

## 🛡️ **Security**

### ❓ Q16: Explain the difference between Authentication and Authorization in Kubernetes.
<details>
<summary>Click to see the answer</summary>

- **Authentication (AuthN)**: Answers the question **"Who are you?"**. It's the process of verifying a user's identity. Kubernetes does not have a built-in user management system. It relies on external authentication methods like client certificates, bearer tokens (JWTs), or OIDC providers (like Dex or a cloud provider's IAM).
- **Authorization (AuthZ)**: Answers the question **"What are you allowed to do?"**. After a user is authenticated, the authorization layer determines if they have permission to perform the requested action. The primary authorization mechanism in Kubernetes is **Role-Based Access Control (RBAC)**.

</details>

### ❓ Q17: What is RBAC and what are its main components?
<details>
<summary>Click to see the answer</summary>

RBAC (Role-Based Access Control) is the standard mechanism for authorization in Kubernetes.

**Main Components**:
1.  **Role** / **ClusterRole**:
    *   A `Role` defines a set of permissions (verbs like `get`, `list`, `create` on resources like `pods`, `deployments`) within a specific **namespace**.
    *   A `ClusterRole` is the same, but its permissions are cluster-wide (not namespaced).
2.  **RoleBinding** / **ClusterRoleBinding**:
    *   A `RoleBinding` grants the permissions defined in a `Role` to a subject (a user, group, or ServiceAccount) within a specific **namespace**.
    *   A `ClusterRoleBinding` grants the permissions of a `ClusterRole` to a subject across the **entire cluster**.

</detaisl>

### ❓ Q18: What is a Security Context in Kubernetes?
<details>
<summary>Click to see the answer</summary>

A Security Context (`securityContext`) is a field in a pod or container manifest that defines privilege and access control settings.

It allows you to control things like:
-   `runAsUser` / `runAsGroup`: Run the process inside the container as a specific user ID instead of root.
-   `readOnlyRootFilesystem`: Make the container's root filesystem read-only.
-   `allowPrivilegeEscalation`: Prevent a process from gaining more privileges than its parent.
-   `capabilities`: Add or drop specific Linux capabilities (e.g., drop `NET_RAW` to prevent packet sniffing).

Setting a restrictive security context is a critical best practice for hardening your containers.

</details>

### ❓ Q19: What are Seccomp and AppArmor and how do they improve container security?
<details>
<summary>Click to see the answer</summary>

Both are Linux security modules that can be used to further restrict what a containerized process is allowed to do.

- **Seccomp (Secure Computing Mode)**: Filters the **system calls** (syscalls) that a process can make to the kernel. You can create a Seccomp profile that defines an allowlist of syscalls. If the process tries to make a syscall that is not on the list, the kernel will terminate it. This greatly reduces the attack surface of the kernel.
- **AppArmor (Application Armor)**: A Mandatory Access Control (MAC) system. It confines programs to a limited set of resources. An AppArmor profile can restrict access to specific files, network ports, or Linux capabilities.

In Kubernetes, you can apply both Seccomp and AppArmor profiles to your pods via annotations or fields in the `securityContext`.

</details>

### ❓ Q20: How would you secure the Kubernetes API server?
<details>
<summary>Click to see the answer</summary>

1.  **Enable Authentication**: Require strong authentication. OIDC is the preferred method for users. Use client certificates for control plane components.
2.  **Enable Authorization**: Always enable RBAC. Disable the legacy ABAC authorizer.
3.  **Use TLS**: Enforce TLS for all communication to and from the API server (`--tls-cert-file` and `--tls-private-key-file`).
4.  **Restrict Network Access**: Make the API server endpoint private if possible. If it must be public, use firewall rules (`--egress-selector-config-file`) or Security Groups to restrict access to trusted IP ranges.
5.  **Enable Audit Logging**: Configure audit logs to record all requests to the API server and ship them to a secure, central location for analysis.
6.  **Rate Limiting**: Configure API server rate limiting to prevent DoS attacks or runaway clients from overwhelming the control plane.

</details>

---

## 💾 **Storage & Cluster Management**

### ❓ Q21: What is the Container Storage Interface (CSI)?
<details>
<summary>Click to see the answer</summary>

CSI is a standard interface that allows container orchestrators (like Kubernetes) to communicate with storage systems (like AWS EBS, Ceph, or NFS).

**The Problem it Solves**: Before CSI, storage driver code was part of the core Kubernetes project ("in-tree"). This meant that adding support for a new storage system required changing Kubernetes itself, which was slow and difficult.

**The Solution**: CSI decouples storage drivers from Kubernetes. A storage vendor can now write a CSI driver for their system and users can install it on their cluster without needing to change Kubernetes. This has allowed for a huge ecosystem of storage integrations to develop.

</details>

### ❓ Q22: How would you perform a backup and restore of an entire Kubernetes application, including its data?
<details>
<summary>Click to see the answer</summary>

The standard tool for this is **Velero**.

**Backup Process**:
1.  **Install Velero**: Deploy Velero to your cluster and configure it with a storage location for backups (like an S3 bucket).
2.  **Install CSI Snapshotter**: Ensure your storage provider's CSI driver supports volume snapshots.
3.  **Create Backup**: `velero backup create my-app-backup --include-namespaces my-app`.
4.  **What it does**: Velero first triggers the CSI driver to take a snapshot of the application's Persistent Volumes. Then, it saves all the Kubernetes object definitions (Deployments, Services, etc.) to the S3 bucket.

**Restore Process**:
`velero restore create --from-backup my-app-backup`.
Velero recreates the Kubernetes objects and tells the CSI driver to provision new Persistent Volumes from the stored snapshots.

</details>

### ❓ Q23: What are the main challenges of running a multi-tenant Kubernetes cluster?
<details>
<summary>Click to see the answer</summary>

Multi-tenancy is when multiple users or teams share the same cluster.

**Challenges**:
1.  **Security Isolation**: Preventing one tenant from accessing another tenant's resources or the underlying node. (Solved with Namespaces, RBAC, Network Policies, PSS).
2.  **Resource Isolation**: Ensuring one tenant cannot consume all the cluster's resources and starve other tenants. (Solved with ResourceQuotas and LimitRanges).
3.  **Network Isolation**: Preventing network cross-talk. (Solved with Network Policies).
4.  **Blast Radius**: A cluster-wide failure (e.g., a CNI issue) can affect all tenants. (This is why many organizations prefer multiple, single-tenant clusters over one large multi-tenant cluster).

</details>

### ❓ Q24: What is Cluster API (CAPI)?
<details>
<summary>Click to see the answer</summary>

Cluster API is a Kubernetes sub-project that provides a declarative, Kubernetes-style API for creating, configuring, and managing Kubernetes clusters themselves.

**The Idea**: You use one Kubernetes cluster (a "management cluster") to manage the lifecycle of many other Kubernetes clusters ("workload clusters"). You define a cluster using CRDs like `kind: Cluster` and `kind: MachineDeployment`. The CAPI controllers on the management cluster then work to provision the underlying infrastructure (e.g., EC2 instances, VPCs) and create the workload cluster.

It aims to make cluster lifecycle management as simple and declarative as managing an application.

</details>

### ❓ Q25: How would you manage a fleet of Kubernetes clusters across multiple regions or clouds?
<details>
<summary>Click to see the answer</summary>

This is a common enterprise challenge.

**My Strategy**:
1.  **Cluster Provisioning**: Use a declarative tool like **Cluster API** or Terraform to provision consistent clusters across all locations.
2.  **Configuration Management**: Use a **GitOps** approach. Have a central Git repository that defines the desired state for applications and cluster add-ons. Use a tool like **ArgoCD ApplicationSets** or **Flux Kustomizations** to automatically deploy the correct configuration to each cluster based on labels (e.g., `region: eu-west-1`, `env: prod`).
3.  **Service Mesh**: Use a multi-cluster service mesh like **Istio** to manage traffic routing, service discovery, and security policies across the entire fleet from a single control plane.
4.  **Centralized Observability**: Federate metrics from each cluster's Prometheus into a central **Thanos** or **Cortex** instance for a global view. Ship logs from all clusters to a central logging backend.

</details>

---

## 🔧 **Troubleshooting**

### ❓ Q26: A pod is stuck in `Pending` state. What are the possible reasons?
<details>
<summary>Click to see the answer</summary>

`Pending` means the pod has been accepted by the API server, but it cannot be scheduled onto a node or one of its containers cannot be started.

Run `kubectl describe pod <pod_name>` and look at the `Events` section.

**Common Reasons**:
-   **Insufficient Resources**: The cluster doesn't have enough free CPU or memory to satisfy the pod's `requests`.
-   **Scheduling Constraints**: The pod cannot be scheduled due to taints/tolerations, node affinity rules, or pod anti-affinity rules.
-   **PVC Not Bound**: The pod is waiting for a PersistentVolumeClaim to be bound, but no suitable PersistentVolume is available.
-   **Cluster Autoscaler Issues**: If you expect a new node to be added, the autoscaler might be failing or hitting cloud provider limits.

</details>

### ❓ Q27: A pod is in `CrashLoopBackOff`. What are your debugging steps?
<details>
<summary>Click to see the answer</summary>

This means the container is starting, crashing, and being restarted repeatedly.

1.  **Check Logs**: The most important step. Check the logs of the *previous*, failed container instance: `kubectl logs <pod_name> --previous`.
2.  **Describe Pod**: `kubectl describe pod <pod_name>`. Look at the `Exit Code` and `Reason` for the last termination.
3.  **Check Liveness Probe**: A failing liveness probe will cause the `kubelet` to kill the container.
4.  **Check Command/Args**: A typo in the container's entrypoint or command can cause it to exit immediately.
5.  **Check Resource Limits**: If the app exceeds its memory limit, it will be `OOMKilled`.

</details>

### ❓ Q28: DNS resolution is failing inside your cluster. How do you debug it?
<details>
<summary>Click to see the answer</summary>

1.  **Check CoreDNS**: Are the CoreDNS pods running? `kubectl get pods -n kube-system -l k8s-app=kube-dns`. Check their logs for errors.
2.  **Check Service**: Does the CoreDNS service exist and have a valid `ClusterIP`? `kubectl get svc -n kube-system kube-dns`.
3.  **Check Pod `resolv.conf`**: Exec into a problematic pod and check its `/etc/resolv.conf`. Does it point to the CoreDNS service's IP? Does it have the correct `search` domains?
4.  **Use `nslookup`**: From inside a pod, try to resolve names:
    *   The service you are trying to reach: `nslookup my-backend-svc`.
    *   A known internal service: `nslookup kubernetes.default`.
    *   An external service: `nslookup google.com`.
5.  **Check Network Policies**: A Network Policy could be blocking DNS traffic on port 53/UDP from your pod to the CoreDNS pods.

</details>

### ❓ Q29: How would you troubleshoot high CPU usage on a worker node?
<details>
<summary>Click to see the answer</summary>

1.  **Identify the Node**: Use `kubectl top nodes` to find the node with high CPU usage.
2.  **Identify the Pods**: Use `kubectl top pods --all-namespaces --sort-by=cpu --node=<node_name>` to see which pods on that node are consuming the most CPU.
3.  **Describe the Pod**: Check the pod's events and status with `kubectl describe pod`.
4.  **Check Application Metrics**: If you have application monitoring (Prometheus), check the pod's metrics dashboards for clues.
5.  **Profile the Application**: If the cause isn't obvious, you may need to use a profiler (like `pprof` for Go, or `perf` for C++)' to see exactly which functions within the application are consuming the CPU.
6.  **Check for Noisy Neighbors**: It's possible a `BestEffort` or `Burstable` pod is consuming all available CPU, starving other pods. Check the QoS classes of the high-CPU pods.

</details>

### ❓ Q30: What is `kube-proxy` and what does it do?
<details>
<summary>Click to see the answer</summary>

`kube-proxy` is a network proxy that runs on every worker node in the cluster. Its job is to implement the Kubernetes `Service` concept.

When you create a Service, it gets a virtual `ClusterIP`. `kube-proxy` watches the API server for new Services and Endpoints (Endpoints are the list of IP addresses of the pods that back a Service). For each Service, `kube-proxy` programs rules on the node (using `iptables` or `IPVS` mode) that say: "any traffic destined for this Service's `ClusterIP` and port should be intercepted and load-balanced across the real IP addresses of the backend pods."

Essentially, it's the component that makes the stable, virtual `ClusterIP` actually route traffic to the ephemeral, changing pod IPs.

</details>
