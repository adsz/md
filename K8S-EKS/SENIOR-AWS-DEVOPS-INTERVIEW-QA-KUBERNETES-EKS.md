# 🎯 Senior AWS DevOps Engineer - Kubernetes & EKS Interview Q&A

> **A guide for advanced, real-world, and tricky questions about running Kubernetes on AWS EKS. Essential for Senior DevOps, SRE, and Platform Engineering roles.**

---

## 🏗️ **EKS Architecture & Design**

### ❓ Q1: Explain the EKS Shared Responsibility Model. What parts are managed by AWS, and what are you responsible for?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
AWS manages the **Control Plane**, and the customer manages the **Data Plane** (the worker nodes) and the applications running on them.

-   **AWS Responsibility (The "Brain")**:
    -   The Kubernetes API Server, `etcd` database, Controller Manager, and Scheduler.
    -   Ensuring the control plane is available, scalable, and patched.
-   **Customer Responsibility (The "Muscle")**:
    -   Provisioning, patching, and securing the **worker nodes** (EC2 or Fargate).
    -   Configuring VPC networking and CNI plugins.
    -   Managing IAM roles for nodes and pods (IRSA).
    -   Deploying, securing, and monitoring applications.

</details>

### ❓ Q2: ⚠️ Tricky Question: Your developers complain about running out of IP addresses in the VPC for their pods. What is the root cause and how do you solve this long-term?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
The root cause is the default behavior of the **AWS VPC CNI plugin**, which assigns a full private IP address from the VPC's CIDR range to each pod. This can quickly exhaust available IPs.

The long-term solution is to enable **VPC CNI Custom Networking**. This allows you to assign pod IPs from a secondary CIDR range that is separate from the main VPC CIDR, effectively giving you a much larger IP space for pods.

---

#### 🧠 **Theoretical Explanation**
By default, the AWS VPC CNI pre-allocates a pool of secondary private IP addresses to each worker node's ENI. The number of IPs (and thus pods) per node is determined by the instance type. For example, an `m5.large` can have up to 29 pods, each taking an IP from your subnet.

**The Solution - Custom Networking**:
1.  You associate one or more secondary, non-overlapping CIDR blocks with your VPC.
2.  You configure the AWS VPC CNI plugin (via the `aws-node` daemonset and `ENIConfig` custom resources) to source pod IPs from these secondary CIDR blocks.
3.  Now, worker nodes still get an IP from the primary VPC CIDR, but pods get their IPs from the secondary CIDR. This decouples pod density from the VPC's primary IP space.

</details>

### ❓ Q3: What are the pros and cons of using EKS with Fargate vs. EC2 nodes?
<details>
<summary>Click to see the answer</summary>

| Feature | EKS on Fargate | EKS on EC2 |
| :--- | :--- | :--- |
| **Management** | **Serverless**. No node management. | **Self-managed**. You manage nodes. |
| **Isolation** | **High**. Each pod runs in its own micro-VM. | **Lower**. Pods share the node's kernel. |
| **Cost Model** | Pay per vCPU/memory used by pod. | Pay for the entire EC2 instance. |
| **Flexibility** | Lower. No daemonsets, no privileged pods. | **Higher**. Full control over node OS, GPU support. |
| **Use Case** | Web apps, APIs, batch jobs. | Long-running services, stateful apps, GPU workloads. |

**Conclusion**: Use **Fargate** for simplicity, security, and for applications with spiky traffic patterns. Use **EC2** when you need maximum control, cost-optimization for steady-state workloads (with Spot/RIs), or specialized hardware like GPUs.

</details>

### ❓ Q4: How would you perform a zero-downtime upgrade of an EKS cluster?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
An EKS upgrade is a two-phase process: first the control plane, then the data plane.
1.  **Control Plane Upgrade**: Initiate the upgrade via the AWS console or API. AWS performs a rolling update of the managed control plane masters with zero downtime.
2.  **Data Plane Upgrade**: After the control plane is done, you must upgrade your worker nodes. The best practice is to use a **rolling update strategy**: create a new, patched node group and gracefully drain and terminate the old nodes.

---

#### 🧠 **Detailed Process**
1.  **Pre-flight Checks**: Use `eksctl` or other tools to check for deprecated APIs that will be removed in the new Kubernetes version. Update your manifests accordingly.
2.  **Control Plane**: Click "Upgrade" in the AWS console for your EKS cluster. This takes 30-60 minutes. The API server remains available throughout.
3.  **Add-on Updates**: Update core add-ons like CoreDNS, `kube-proxy`, and the VPC CNI plugin to versions compatible with the new control plane.
4.  **New Node Group**: Create a new Managed Node Group (or ASG) with an EKS-Optimized AMI for the new Kubernetes version.
5.  **Cordon and Drain**: Cordon the old nodes to prevent new pods from being scheduled on them (`kubectl cordon <node_name>`). Then, gracefully drain the pods from the old nodes (`kubectl drain <node_name> --ignore-daemonsets --delete-local-data`). The Kubernetes scheduler will reschedule these pods onto the new nodes.
6.  **Decommission**: Once the old nodes are empty, terminate them by deleting the old node group.

**Important**: Ensure your applications have multiple replicas and properly configured Pod Disruption Budgets (PDBs) to handle the graceful draining without causing an outage.

</details>

### ❓ Q5: What is Karpenter and how does it differ from the standard Cluster Autoscaler?
<details>
<summary>Click to see the answer</summary>

- **Cluster Autoscaler (CA)**: The traditional way. It scales the **number of nodes** within pre-defined Auto Scaling Groups (ASGs). It is limited to the instance types you have defined in your ASG's Launch Template.
- **Karpenter**: A newer, more flexible cluster autoscaler from AWS. It is **not tied to ASGs**. It watches for pending pods and provisions the most optimal, cheapest node that can fit the pod's requirements directly. It can choose from a wide variety of instance types on the fly.

| Feature | Cluster Autoscaler | Karpenter |
| :--- | :--- | :--- |
| **Mechanism** | Scales existing ASGs. | Provisions nodes directly. |
| **Flexibility** | Limited to instance types in ASG. | **Can choose any instance type.** |
| **Efficiency** | Can lead to waste (bin-packing). | **More efficient bin-packing.** |
| **Speed** | Slower (waits for ASG). | **Faster (provisions directly).** |
| **Best For** | Simpler, legacy setups. | **Cost optimization, performance, flexibility.** |

</details>

---

## 🌐 **EKS Networking**

### ❓ Q6: What is a CNI plugin in Kubernetes, and why is the AWS VPC CNI special?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
A **CNI (Container Network Interface)** plugin is responsible for all pod networking: assigning IP addresses to pods and managing connectivity between them.

The **AWS VPC CNI** is special because, unlike most CNIs that use a virtual overlay network, it assigns each pod a **real IP address from the VPC**. This makes pods first-class citizens in your AWS network, allowing them to interact seamlessly with other AWS services and be targeted directly by load balancers.

</details>

### ❓ Q7: Your application requires fine-grained network policies (e.g., allow traffic from `frontend` pods to `backend` pods on a specific port, but deny all other traffic). How do you achieve this in EKS?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
The default AWS VPC CNI does not enforce Kubernetes `NetworkPolicy` resources. To achieve this, you need to install a network policy engine. The most common solution is to install **Calico**.

---

#### 🧠 **Theoretical Explanation**
1.  **Install Calico**: You deploy the Calico operator and custom resources to your EKS cluster. Calico runs as a daemonset on each node.
2.  **Define Network Policies**: You create standard Kubernetes `NetworkPolicy` objects.
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: backend-allow-frontend
      namespace: my-app
    spec:
      podSelector:
        matchLabels:
          app: backend
      policyTypes:
        - Ingress
      ingress:
        - from:
            - podSelector:
                matchLabels:
                  app: frontend
          ports:
            - protocol: TCP
              port: 8080
    ```
3.  **Enforcement**: Calico's agent on each node (`calico-node`) watches for these policies and programs the node's Linux kernel (using `iptables` or `eBPF`) to enforce these rules, allowing or dropping packets as defined.

**Note**: AWS now offers a native add-on for network policy enforcement, which also uses a downstream version of Calico, providing a more integrated experience.

</details>

### ❓ Q8: What is an Ingress Controller and compare AWS Load Balancer Controller vs. NGINX Ingress Controller.
<details>
<summary>Click to see the answer</summary>

An **Ingress Controller** is a component in the cluster that watches for Kubernetes `Ingress` resources and provisions an external load balancer to route traffic from the internet to services inside the cluster.

| Feature | AWS Load Balancer Controller | NGINX Ingress Controller |
| :--- | :--- | :--- |
| **Load Balancer** | Provisions a real **AWS Application Load Balancer (ALB)**. | Provisions a **Network Load Balancer (NLB)** that forwards traffic to NGINX pods running in the cluster. |
| **Cost** | Pay for the ALB. | Pay for the NLB + the EC2 resources for the NGINX pods. |
| **Features** | Integrates with AWS WAF, Cognito, Global Accelerator. | Highly customizable with NGINX snippets, supports more rewrite rules. |
| **Management** | Managed by AWS (the ALB itself). | You manage the NGINX pods (updates, scaling). |
| **Best For** | Deep AWS integration, simplicity. | Advanced routing, customization, multi-cloud portability. |

</details>

### ❓ Q9: What is a Service Mesh (like Istio or AWS App Mesh) and what problems does it solve?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
A Service Mesh is a dedicated infrastructure layer for making service-to-service communication safe, fast, and reliable. It works by injecting a "sidecar" proxy (like Envoy) next to each of your application containers. All traffic between services is routed through these proxies.

**It solves problems like**:
-   **Observability**: Automatically get metrics, logs, and traces for all service traffic.
-   **Security**: Enforce mutual TLS (mTLS) to encrypt all traffic within the cluster.
-   **Traffic Management**: Implement advanced routing like canary releases, A/B testing, and circuit breaking without changing application code.

</detaisl>

### ❓ Q10: How does the AWS Load Balancer Controller's "IP Mode" vs. "Instance Mode" work for targeting pods?
<details>
<summary>Click to see the answer</summary>

- **Instance Mode (Default/Legacy)**: The ALB targets the **NodePort** on the worker node. Traffic flows `Client -> ALB -> Node -> Kube-proxy (iptables) -> Pod`. This involves an extra network hop and can have issues with SNAT, sometimes obscuring the client's source IP.
- **IP Mode (Recommended)**: The ALB targets the **pod's IP address directly**. Traffic flows `Client -> ALB -> Pod`. This is more efficient, has lower latency, and preserves the client's source IP address. This is the preferred mode for most applications.

</details>

---

## 🔐 **EKS Security**

### ❓ Q11: How do you grant pods specific AWS permissions (e.g., to access an S3 bucket) without giving those permissions to the entire worker node?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
I would use **IAM Roles for Service Accounts (IRSA)**. This is the standard, most secure way to grant AWS permissions to pods in EKS.

It works by associating a Kubernetes Service Account with an AWS IAM Role. Any pod that uses that Service Account can then assume the associated IAM Role and get temporary AWS credentials to access only the services defined in the role's policy.

---

#### 🧠 **Theoretical Explanation**
IRSA leverages **OIDC (OpenID Connect)** and **AWS STS**.
1.  **EKS OIDC Provider**: You create an OIDC Identity Provider in IAM for your EKS cluster.
2.  **IAM Role & Trust Policy**: You create an IAM Role with the specific permissions. The role's trust policy is configured to allow assumption only by a specific Kubernetes Service Account from your cluster's OIDC provider.
3.  **Kubernetes Service Account**: You create a Service Account in Kubernetes and annotate it with the ARN of the IAM Role.
4.  **At Runtime**: The AWS SDK inside your pod uses a projected service account token to call `sts:AssumeRoleWithWebIdentity`. STS validates the token with the OIDC provider and returns temporary AWS credentials to the pod.

This process completely bypasses the worker node's IAM role, achieving true least-privilege for pods.

</details>

### ❓ Q12: What are Pod Security Standards and how do you enforce them in EKS?
<details>
<summary>Click to see the answer</summary>

**Pod Security Standards (PSS)** are the successor to Pod Security Policies (PSPs). They are standard security profiles for pods, ranging from `privileged` (unrestricted) to `baseline` (minimally restrictive) to `restricted` (highly restrictive).

**Enforcement**: You can enforce these standards at the **namespace level** using labels.
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-restricted-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
```
When you label a namespace, the built-in **Pod Security Admission Controller** will block any new pods that don't meet the specified security profile.

</details>

### ❓ Q13: How would you scan container images for vulnerabilities before deploying them to EKS?
<details>
<summary>Click to see the answer</summary>

My strategy would be to integrate scanning into the CI/CD pipeline:
1.  **CI Pipeline Scan**: After the `docker build` step, I would use a tool like **Trivy** or **Snyk** to scan the newly built image for known CVEs. If a high or critical vulnerability is found, the pipeline fails.
2.  **Registry Scan**: I would use **Amazon ECR's built-in image scanning**. This can be configured to scan on push, and it continuously re-scans images as new vulnerabilities are discovered.
3.  **Admission Controller (Advanced)**: For maximum security, I would use an **admission controller** in the cluster (like OPA/Gatekeeper or Kyverno) to block the deployment of any image that hasn't been scanned or that has known critical vulnerabilities.

</details>

### ❓ Q14: What is OPA/Gatekeeper and how can it be used for policy-as-code in Kubernetes?
<details>
<summary>Click to see the answer</summary>

**OPA (Open Policy Agent)** is an open-source policy engine. **Gatekeeper** is a Kubernetes-native project that integrates OPA as an admission controller.

It allows you to enforce custom policies on your cluster beyond what standard RBAC or PSS can do. You write policies in a language called **Rego**.

**Use Cases**:
-   Enforce that all images must come from a trusted registry (e.g., your company's ECR).
-   Require that all pods must have resource `requests` and `limits` set.
-   Ensure all Ingress objects use HTTPS.
-   Mandate that all resources must have a `team` and `cost-center` label.

Gatekeeper intercepts every request to the Kubernetes API and checks it against your policies before it is persisted to `etcd`.

</details>

### ❓ Q15: How do you manage secrets for applications running in EKS?
<details>
<summary>Click to see the answer</summary>

While Kubernetes has native `Secret` objects, they are only base64 encoded, not encrypted. The enterprise standard is to use an external secrets management system.

**The Best Practice**: **External Secrets Operator (ESO)**.
1.  **Store Secrets**: Store your secrets securely in **AWS Secrets Manager** or **HashiCorp Vault**.
2.  **Deploy ESO**: Install the External Secrets Operator in your cluster.
3.  **Grant Permissions**: Give the operator permissions to read secrets from your chosen backend (e.g., using IRSA).
4.  **Define `ExternalSecret`**: You create a custom resource called `ExternalSecret` in your application's namespace.
    ```yaml
    apiVersion: external-secrets.io/v1beta1
    kind: ExternalSecret
    metadata:
      name: my-db-secret
    spec:
      refreshInterval: "1h"
      secretStoreRef:
        name: aws-secrets-manager
        kind: ClusterSecretStore
      target:
        name: db-credentials # This is the k8s Secret that will be created
      data:
      - secretKey: username
        remoteRef:
          key: my-app/db-secret # Key in AWS Secrets Manager
          property: username
    ```
5.  **Sync**: The operator reads the secret from AWS Secrets Manager and automatically creates and syncs a native Kubernetes `Secret` in your namespace, which your application can then consume normally.

This approach keeps the secret management lifecycle outside the cluster and provides a secure, automated way to inject secrets into your applications.

</details>

---

## 💾 **Storage & State**

### ❓ Q16: How do you provide persistent storage to stateful applications in EKS?
<details>
<summary>Click to see the answer</summary>

I would use the **EBS CSI (Container Storage Interface) Driver**. This is the standard way to integrate Amazon EBS volumes with EKS.

**The Workflow**:
1.  **Install Driver**: Deploy the EBS CSI Driver to the cluster. It runs as a controller and a daemonset.
2.  **Create StorageClass**: Define a `StorageClass` resource that specifies the EBS volume type (e.g., `gp3`), and other parameters.
3.  **Create PersistentVolumeClaim (PVC)**: The application developer creates a PVC requesting a certain amount of storage.
4.  **Dynamic Provisioning**: The EBS CSI Driver sees the PVC, calls the AWS API to create a new EBS volume, and creates a corresponding `PersistentVolume` (PV) object in Kubernetes.
5.  **Mounting**: When a pod requests the PVC, Kubernetes automatically attaches the EBS volume to the correct worker node and mounts it into the pod.

</details>

### ❓ Q17: Compare EBS and EFS for use with EKS. When would you choose one over the other?
<details>
<summary>Click to see the answer</summary>

- **EBS (Elastic Block Store)**: Provides **block-level** storage. An EBS volume can only be mounted to a **single pod at a time** (ReadWriteOnce access mode). It is tied to a specific Availability Zone. It's perfect for single-replica stateful applications like databases (e.g., a single PostgreSQL pod).
- **EFS (Elastic File System)**: Provides a **file system** interface (NFS). An EFS volume can be mounted by **many pods simultaneously**, even across different Availability Zones (ReadWriteMany access mode). It's perfect for applications that need a shared file system, like WordPress, content management systems, or development tools like Jenkins.

</details>

### ❓ Q18: How would you back up and restore stateful applications and their data in EKS?
<details>
<summary>Click to see the answer</summary>

#### 💡 **Simple Answer**
The industry standard tool for this is **Velero**.

---

#### 🧠 **Theoretical Explanation**
Velero is an open-source tool that can back up and restore Kubernetes cluster resources and persistent volumes.

**Backup Process**:
1.  **Install Velero**: Deploy Velero to your cluster and configure it with a storage location for backups (like an S3 bucket) and credentials to access it.
2.  **CSI Snapshotting**: Install the AWS EBS CSI Driver and the `VolumeSnapshotClass` required for taking volume snapshots.
3.  **Create Backup**: You can create backups on-demand or on a schedule.
    ```bash
    velero backup create my-app-backup --include-namespaces my-app
    ```
4.  **What it does**: Velero first calls the EBS CSI driver to take a point-in-time snapshot of the application's EBS volume. Then, it queries the Kubernetes API to get all the resource definitions (Deployments, Services, ConfigMaps, etc.) in the specified namespace and saves them as a gzipped tarball in the S3 bucket alongside the snapshot information.

**Restore Process**:
```bash
velero restore create --from-backup my-app-backup
```
Velero reads the resource definitions from the S3 bucket, recreates them in the cluster, and then tells the EBS CSI driver to provision a new EBS volume from the snapshot and attach it to the restored pod.

</details>

### ❓ Q19: What is a `StatefulSet` and how does it differ from a `Deployment`?
<details>
<summary>Click to see the answer</summary>

- **Deployment**: Designed for **stateless** applications. Pods are identical and interchangeable. They get random hostnames (e.g., `my-app-5f8d...`) and can be scaled up or down in any order.
- **StatefulSet**: Designed for **stateful** applications that require stable, unique identities. Pods created by a StatefulSet have:
    - **Stable, predictable names**: e.g., `my-db-0`, `my-db-1`.
    - **Stable, persistent storage**: Pod `my-db-0` will always be associated with the same persistent volume claim.
    - **Ordered deployment and scaling**: Pods are created and terminated in a strict order (0, 1, 2...). `my-db-1` will not start until `my-db-0` is ready.

**Use Case**: Clustered databases like ZooKeeper, Kafka, or Elasticsearch.

</details>

### ❓ Q20: What challenges do you face when running a database in Kubernetes, and what are the best practices?
<details>
<summary>Click to see the answer</summary>

**Challenges**:
-   **Storage**: Requires robust, persistent, and performant storage.
-   **Networking**: Needs stable network identities and DNS.
-   **Lifecycle Management**: Upgrades, backups, and failover are complex.
-   **Day 2 Operations**: Monitoring, logging, and tuning are difficult.

**Best Practices**:
1.  **Use a Kubernetes Operator**: For any serious database, use a dedicated Operator (e.g., Crunchy Data for PostgreSQL, Zalando Operator for PostgreSQL, Presslabs for MySQL). The Operator encapsulates the domain knowledge required to run the database correctly.
2.  **Use `StatefulSets`**: To manage the database pods.
3.  **Use Persistent Storage**: With the appropriate CSI driver and fast EBS volumes (`io2` or `gp3`).
4.  **Use Pod Anti-Affinity**: To ensure database replicas are scheduled on different worker nodes for high availability.
5.  **Separate Node Group**: Run your database on a dedicated node group with appropriate instance types and taints to prevent other applications from running on them.
6.  **Consider Managed Services**: For most use cases, running a database in Kubernetes is complex. **Using a managed service like Amazon RDS or Aurora is often the more reliable, scalable, and operationally simple choice.** You can still connect to it from your applications running in EKS.

</details>

---

## 🔬 **Observability & Troubleshooting**

### ❓ Q21: How would you design and implement a monitoring and alerting stack for EKS?
<details>
<summary>Click to see the answer</summary>

My go-to stack would be **Prometheus, Grafana, and Alertmanager**.

1.  **Prometheus**: The core monitoring engine. I would deploy it using the `kube-prometheus-stack` Helm chart, which provides a batteries-included setup.
    *   It automatically discovers and scrapes metrics from the Kubernetes API server, nodes (`node-exporter`), and pods.
    *   I would configure `ServiceMonitor` custom resources to tell Prometheus how to scrape metrics from my applications.
2.  **Grafana**: The visualization layer. I would deploy it alongside Prometheus and use it to create dashboards for:
    *   Cluster health (CPU, memory, disk usage).
    *   Application performance (request latency, error rates - RED metrics).
    *   Kubernetes object status (pod restarts, pending pods).
3.  **Alertmanager**: Handles alerting. I would define alerting rules in Prometheus. When a rule fires, Prometheus sends the alert to Alertmanager, which then handles deduplication, grouping, and routing the alert to the correct destination (e.g., PagerDuty, Slack, email).

</details>

### ❓ Q22: How do you handle log aggregation for applications in EKS?
<details>
<summary>Click to see the answer</summary>

The standard pattern is to use a **logging agent** deployed as a **DaemonSet**.

1.  **Application Logging**: Developers configure their applications to write logs to `stdout` and `stderr`. This is a container best practice.
2.  **Logging Agent**: I would deploy **Fluent Bit** as a DaemonSet. Fluent Bit is lightweight and efficient.
3.  **Log Collection**: The Fluent Bit pod on each node mounts the host's log directories (`/var/log/pods`, `/var/log/containers`). It reads the container log files, enriches them with Kubernetes metadata (pod name, namespace, labels), and forwards them to a centralized logging backend.
4.  **Logging Backend**: The backend could be **Amazon OpenSearch Service**, **Loki**, **Datadog**, or **Splunk**. This is where logs are stored, indexed, and can be searched and visualized.

</details>

### ❓ Q23: A pod is stuck in `CrashLoopBackOff` state. What are your steps to debug this?
<details>
<summary>Click to see the answer</summary>

`CrashLoopBackOff` means the container is starting, crashing, and then Kubernetes is repeatedly trying to restart it.

**Debugging Steps**:
1.  **Describe the Pod**: `kubectl describe pod <pod_name> -n <namespace>`. This will show me the pod's events, status, exit code of the last termination, and any error messages.
2.  **Check the Logs**: The container might be logging an error right before it crashes. I need to check the logs of the *previous* failed container instance: `kubectl logs <pod_name> -n <namespace> --previous`.
3.  **Check for Misconfiguration**: A common cause is a configuration error (e.g., wrong database endpoint, missing secret). I would check the pod's `ConfigMaps` and `Secrets`.
4.  **Check Liveness/Readiness Probes**: A misconfigured liveness probe that is failing could be causing `kubelet` to kill the container. I would check the probe's configuration (`initialDelaySeconds`, `timeoutSeconds`, the command/HTTP endpoint itself).
5.  **Exec into the Container (if possible)**: If the container runs for a few seconds before crashing, I might be able to get a shell into it to investigate: `kubectl exec -it <pod_name> -n <namespace> -- /bin/sh`.
6.  **Check Resource Limits**: If the application is exceeding its memory limits, it will be OOMKilled by the kernel. `kubectl describe pod` will show the reason as `OOMKilled`.

</details>

### ❓ Q24: A pod is stuck in `ImagePullBackOff` state. What are the possible causes?
<details>
<summary>Click to see the answer</summary>

This means `kubelet` cannot pull the container image from the registry.

**Possible Causes**:
1.  **Typo**: The image name or tag in the pod manifest is incorrect.
2.  **Registry Unreachable**: A network issue is preventing the worker node from reaching the container registry (e.g., ECR). This could be a problem with NACLs, Security Groups, or NAT Gateways.
3.  **Authentication Error**: The node does not have permission to pull from the registry. For a private ECR registry, this means the worker node's IAM role is missing the required ECR permissions (`ecr:GetDownloadUrlForLayer`, `ecr:BatchGetImage`, etc.).
4.  **Image Doesn't Exist**: The specified image tag was never pushed to the registry.
5.  **Rate Limiting**: Public registries like Docker Hub have strict rate limits. The cluster might have exceeded them.

</details>

### ❓ Q25: How does DNS work inside a Kubernetes cluster?
<details>
<summary>Click to see the answer</summary>

Kubernetes has its own internal DNS service, which is typically **CoreDNS** in modern clusters (it replaced `kube-dns`).

1.  **CoreDNS Deployment**: CoreDNS runs as a `Deployment` with a `Service` in the `kube-system` namespace.
2.  **Pod Configuration**: The `kubelet` on each node configures each pod's `/etc/resolv.conf` file to point to the CoreDNS service's ClusterIP.
3.  **Service Discovery**: When a pod wants to talk to another service (e.g., `my-backend-svc`), it makes a DNS query for `my-backend-svc`. CoreDNS resolves this to the ClusterIP of the `my-backend-svc` Service.
4.  **Fully Qualified Domain Name (FQDN)**: The full DNS name for a service is `<service-name>.<namespace>.svc.cluster.local`.
5.  **External Resolution**: If a query is for an external domain (e.g., `google.com`), CoreDNS will forward the request to the upstream DNS server it inherited from the worker node.

</details>

---

## 🚀 **CI/CD & GitOps**

### ❓ Q26: Compare and contrast ArgoCD and Flux for implementing GitOps on EKS.
<details>
<summary>Click to see the answer</summary>

Both are leading CNCF projects for GitOps, but they have different approaches.

| Feature | ArgoCD | FluxCD |
| :--- | :--- | :--- |
| **Architecture** | Centralized. A central ArgoCD instance manages many clusters. | Decentralized. Each cluster has its own Flux operators. |
| **User Interface** | **Excellent web UI**. Great for visualization and manual syncs. | Primarily CLI and Git-driven. Has an optional UI. |
| **Sync Model** | Primarily pull-based, but UI allows manual push-like sync. | Strictly pull-based. |
| **Multi-tenancy** | Strong multi-tenancy features with projects and RBAC. | Simpler, namespace-focused security model. |
| **Setup** | More components to install. | Simpler, more modular installation. |

**Conclusion**: Choose **ArgoCD** if you need a powerful UI, centralized control, and multi-tenancy for a platform team. Choose **Flux** if you prefer a more decentralized, Git-native, and modular approach.

</details>

### ❓ Q27: How would you implement a progressive delivery (e.g., canary release) strategy for an application on EKS?
<details>
<summary>Click to see the answer</summary>

I would use a GitOps tool like **ArgoCD** or **Flux** combined with a progressive delivery controller like **Argo Rollouts** or **Flagger**.

**The Workflow with Argo Rollouts**:
1.  **Replace `Deployment`**: Instead of a standard `Deployment` object, you create a `Rollout` custom resource. It looks very similar but has an extra `strategy` section.
2.  **Define Canary Strategy**: In the `Rollout` object, you define the canary steps.
    ```yaml
    strategy:
      canary:
        steps:
        - setWeight: 10
        - pause: {duration: 5m}
        - setWeight: 50
        - pause: {duration: 10m}
    ```
3.  **Trigger Release**: When you update the image tag in your Git repository, ArgoCD applies the change to the `Rollout` object.
4.  **Automated Rollout**: Argo Rollouts takes over. It creates a new `ReplicaSet` for the canary version and works with a Service Mesh (like Istio) or an Ingress Controller to split the traffic (e.g., sending 10% of traffic to the new version).
5.  **Automated Analysis**: During the `pause`, Argo Rollouts can query a metrics provider (like Prometheus) to check for errors or latency issues. If metrics are good, it proceeds to the next step. If they are bad, it automatically rolls back the release.

</details>

### ❓ Q28: What is Helm and why is it useful?
<details>
<summary>Click to see the answer</summary>

**Helm** is the package manager for Kubernetes.

It allows you to:
1.  **Package Applications**: Bundle all the Kubernetes manifests needed for an application (Deployments, Services, ConfigMaps, etc.) into a single package called a **Chart**.
2.  **Manage Complexity**: Use Go templating to create configurable and reusable manifests. Instead of hardcoding values, you can use variables from a `values.yaml` file.
3.  **Manage Releases**: Helm tracks versions of your releases, making it easy to upgrade applications and roll back to a previous version if something goes wrong (`helm upgrade`, `helm rollback`).

It simplifies the process of deploying and managing even very complex applications on Kubernetes.

</details>

### ❓ Q29: How do you manage Helm charts in an enterprise environment?
<details>
<summary>Click to see the answer</summary>

1.  **Chart Repository**: We would use **ChartMuseum** or a generic artifact repository like **JFrog Artifactory** or **Nexus** to host our internal, versioned Helm charts.
2.  **CI/CD for Charts**: We would have a separate CI/CD pipeline for our Helm charts that includes:
    *   **Linting**: `helm lint` to check for syntax errors.
    *   **Testing**: `helm test` to run tests against a deployed chart.
    *   **Versioning**: Automatically incrementing the chart version based on semantic versioning.
    *   **Publishing**: Pushing the packaged chart to our internal ChartMuseum.
3.  **Umbrella Charts**: For complex applications, we would use an "umbrella" chart that lists other charts as dependencies in its `Chart.yaml`, allowing us to deploy an entire application stack with a single Helm command.
4.  **Provenance and Signing**: We would sign our charts using GPG to ensure their integrity and prove their origin.

</details>

### ❓ Q30: What is Kustomize and how does it compare to Helm?
<details>
<summary>Click to see the answer</summary>

**Kustomize** is a template-free way to customize application configuration. It's built into `kubectl`.

-   **How it works**: You start with a base set of standard Kubernetes YAML manifests. Then, for each environment (dev, staging, prod), you create an `overlay` that specifies only the *differences* for that environment (e.g., change the number of replicas, update an image tag, add a label). Kustomize then merges the base with the overlay to generate the final YAML.

| Feature | Helm | Kustomize |
| :--- | :--- | :--- |
| **Templating** | Yes (Go templating). | **No (template-free)**. Uses overlays. |
| **Packaging** | Yes (Charts). | No (uses plain YAML files). |
| **Complexity** | Higher learning curve. | Simpler, easier to start. |
| **Use Case** | Distributing configurable, reusable applications. | Customizing applications for specific environments. |

**Conclusion**: They are not mutually exclusive. A common pattern is to use **Helm** to deploy a third-party application (like Prometheus) and then use **Kustomize** to apply your environment-specific configurations on top of it.

</details>