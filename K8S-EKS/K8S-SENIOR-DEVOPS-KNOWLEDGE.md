# 🚀 Kubernetes - Senior DevOps Engineer Knowledge Base

> **🎯 Deep Dive Interview Prep Guide** - Master K8s theory and practice for senior roles

---

## 📚 Core Concepts - Architecture Deep Dive

### 🏗️ Why Kubernetes Architecture Works This Way

#### **Control Plane Components Theory**

Kubernetes follows a **declarative model** rather than imperative. This fundamental design choice means:

- **You declare the desired state** (e.g., "I want 3 replicas")
- **The system continuously reconciles** actual state to match desired state
- **Self-healing becomes automatic** - if reality diverges, K8s fixes it

**Why Master-Worker Architecture?**
- **Separation of concerns**: Control plane makes global decisions, workers execute
- **Scalability**: Can scale workers independently of control plane
- **Fault tolerance**: Control plane can be made HA separately from workloads
- **Security**: Sensitive cluster state isolated from user workloads

| Component | **Why It Exists** | **What Problems It Solves** |
|-----------|-------------------|----------------------------|
| **🧠 API Server** | Central communication hub | Provides single source of truth, authentication gateway, admission control |
| **⚡ etcd** | Distributed consistent storage | Ensures cluster state survives failures, provides watch functionality for changes |
| **🎛️ Controller Manager** | Implements control loops | Maintains desired state automatically without manual intervention |
| **📋 Scheduler** | Optimal pod placement | Ensures efficient resource utilization and constraint satisfaction |
| **🔧 kubelet** | Node-level enforcement | Bridges container runtime with K8s, ensures pods match specifications |
| **🌐 kube-proxy** | Service abstraction | Enables stable networking despite pod ephemerality |

<details>
<summary>📘 Click to see Architecture Implementation Example</summary>

```yaml
# Example showing how architecture components interact
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3  # Desired state stored in etcd
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        resources:
          requests:
            memory: "64Mi"  # Scheduler uses this
            cpu: "250m"     # for placement decisions
          limits:
            memory: "128Mi"
            cpu: "500m"

# Flow:
# 1. API Server receives this manifest
# 2. Stores in etcd after validation
# 3. Controller Manager sees deployment needs 3 pods
# 4. Creates 3 pod objects
# 5. Scheduler assigns pods to nodes
# 6. Kubelet on each node starts containers
# 7. Kube-proxy updates iptables for service routing
```

</details>

---

## 🧩 Pod Lifecycle - The Theory Behind It

### **Why Pods, Not Just Containers?**

Kubernetes introduced **Pods as the atomic unit** rather than containers because:

1. **Co-scheduling needs**: Some containers must run together (sidecar pattern)
2. **Shared resources**: Containers in a pod share network namespace and storage
3. **Atomic lifecycle**: All containers in a pod live and die together
4. **Single deployable unit**: Simplifies deployment and scaling logic

### **Pod Phases Explained**

| Phase | **What's Happening** | **Why This Matters** |
|-------|---------------------|---------------------|
| **Pending** | Scheduler finding node, image pulling | Resource availability check |
| **Running** | At least one container running | Normal operation state |
| **Succeeded** | All containers terminated successfully | Jobs/batch workloads |
| **Failed** | All containers terminated, at least one failed | Error handling needed |
| **Unknown** | Cannot determine state | Network/communication issues |

<details>
<summary>📘 Click to see Pod Lifecycle Example</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: lifecycle-demo
spec:
  initContainers:  # Run before main containers
  - name: init-myservice
    image: busybox
    command: ['sh', '-c', 'until nslookup myservice; do echo waiting; sleep 2; done;']
  
  containers:
  - name: main-app
    image: nginx
    lifecycle:
      postStart:  # Runs immediately after container starts
        exec:
          command: ["/bin/sh", "-c", "echo Hello from postStart > /usr/share/message"]
      preStop:  # Runs before container stops
        exec:
          command: ["/usr/sbin/nginx", "-s", "quit"]
    
    livenessProbe:  # Restarts container if fails
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    
    readinessProbe:  # Removes from service if fails
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
```

</details>

---

## 🎯 Workload Resources - Design Philosophy

### **Why Different Workload Types?**

Kubernetes provides different workload resources because **applications have fundamentally different operational requirements**:

#### **📦 Deployment - For Stateless Applications**

**Design Philosophy:**
- **Pods are interchangeable** - any pod can handle any request
- **Rolling updates are safe** - no data loss when replacing pods
- **Horizontal scaling is simple** - just add more replicas

**Why it works this way:**
- Uses **ReplicaSet** controller underneath for maintaining replica count
- Supports **multiple update strategies** because stateless apps can handle various rollout patterns
- **Revision history** enables quick rollbacks without data considerations

#### **🗂️ StatefulSet - For Stateful Applications**

**Design Philosophy:**
- **Stable, unique network identities** - pod-0, pod-1, pod-2 (not random hashes)
- **Ordered deployment and scaling** - pod-0 must be ready before pod-1 starts
- **Persistent storage** - each pod gets its own PersistentVolume

**Why it works this way:**
- Databases need **predictable hostnames** for clustering (mysql-0.mysql.default.svc.cluster.local)
- **Ordered startup** ensures primary is ready before secondaries
- **Ordered termination** (reverse order) prevents data loss
- **No automatic PVC deletion** - data persists even after StatefulSet deletion

#### **🛡️ DaemonSet - For Node-Level Services**

**Design Philosophy:**
- **Exactly one pod per node** - system-level services
- **Automatic scheduling** to new nodes
- **Tolerates node taints** by default

**Why it works this way:**
- Node monitoring, log collection, network plugins need **node-level presence**
- **No replica count** - determined by node count
- **Immediate scheduling** to new nodes without manual intervention

#### **📋 Job and CronJob - For Batch Processing**

**Design Philosophy:**
- **Job**: Run to completion tasks, ensures specified number of successful completions
- **CronJob**: Scheduled recurring tasks, like Unix cron

**Why these exist:**
- **Different lifecycle** than services - meant to finish, not run forever
- **Retry logic built-in** - handles failures automatically
- **Parallelism support** - can run multiple pods concurrently
- **Completion tracking** - knows when work is done

---

## 🚀 Deployment Strategies - Theory and Patterns

### **Built-in Update Strategies**

#### **Recreate Strategy - Complete Replacement**

**Philosophy:**
- **All old pods terminated before new ones start**
- **Downtime is acceptable** for the application
- **Simple and predictable** update process

**Why use Recreate:**
- **Version incompatibility** - old and new versions can't coexist
- **Resource constraints** - can't run double the pods temporarily
- **Database migrations** - need clean cutover
- **Development environments** - downtime acceptable

#### **RollingUpdate Strategy - Zero Downtime**

**Philosophy:**
- **Gradual replacement** of old pods with new ones
- **Maintains availability** throughout update
- **Configurable pace** via maxUnavailable and maxSurge

**Parameters explained:**
- **maxUnavailable**: Maximum pods that can be down during update (number or percentage)
- **maxSurge**: Maximum pods above desired replica count during update
- **Why both?** Balance between update speed and resource usage

### **Advanced Deployment Patterns**

#### **🔵🟢 Blue/Green Deployment**

**Philosophy:**
- **Two complete environments** running simultaneously
- **Instant cutover** via service selector or load balancer
- **Quick rollback** capability

**Why Blue/Green:**
- **Zero downtime** deployment
- **Full testing** of new version before switch
- **Database migrations** easier to manage
- **Instant rollback** if issues detected

**Implementation approach:**
1. Deploy new version (Green) alongside old (Blue)
2. Test Green environment thoroughly
3. Switch traffic to Green
4. Keep Blue for quick rollback

#### **🐤 Canary Deployment**

**Philosophy:**
- **Gradual rollout** to subset of users
- **Risk mitigation** through incremental exposure
- **Metrics-driven** promotion or rollback

**Why Canary:**
- **Minimize blast radius** of bad deployments
- **Real user testing** with limited exposure
- **Performance validation** under real load
- **A/B testing** capabilities

**Typical progression:**
- 5% traffic → monitor metrics → 25% → 50% → 100%

#### **🔬 A/B Testing Pattern**

**Philosophy:**
- **Multiple versions** running simultaneously
- **User segmentation** based on rules
- **Business metrics** drive decisions

**Why A/B Testing:**
- **Feature validation** with real users
- **Performance comparison** between versions
- **User experience** optimization
- **Data-driven decisions** for features

#### **👻 Shadow (Dark Launch) Deployment**

**Philosophy:**
- **Mirror production traffic** to new version
- **No user impact** - responses not sent to clients
- **Real load testing** without risk

**Why Shadow deployment:**
- **Performance validation** under real load
- **Bug detection** without user impact
- **Capacity planning** for new version
- **Integration testing** with real data

#### **📈 Progressive Delivery**

**Philosophy:**
- **Automated canary/blue-green** deployments
- **Metrics-driven promotion** or rollback
- **GitOps integration** for declarative rollouts

**Tools and frameworks:**
- **Argo Rollouts**: Advanced deployment strategies for K8s
- **Flagger**: Progressive delivery operator
- **Istio/Linkerd**: Service mesh for traffic management

**Why Progressive Delivery:**
- **Reduces manual intervention** in deployments
- **Consistent rollout process** across teams
- **Automatic rollback** on metric degradation
- **Audit trail** of deployment decisions

<details>
<summary>📘 Click to see Deployment Strategy Examples</summary>

```yaml
# RECREATE STRATEGY
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-recreate
spec:
  replicas: 3
  strategy:
    type: Recreate  # All pods killed before new ones start
  template:
    spec:
      containers:
      - name: app
        image: myapp:v2.0

---
# ROLLING UPDATE WITH CUSTOM PARAMETERS
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-rolling
spec:
  replicas: 10
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%  # Max 2-3 pods down during update
      maxSurge: 25%        # Max 2-3 extra pods during update
  template:
    spec:
      containers:
      - name: app
        image: myapp:v2.0

---
# BLUE/GREEN WITH SERVICE SWITCHING
# Blue deployment (current)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-blue
  labels:
    version: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
      version: blue
  template:
    metadata:
      labels:
        app: myapp
        version: blue
    spec:
      containers:
      - name: app
        image: myapp:v1.0

---
# Green deployment (new)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-green
  labels:
    version: green
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
      version: green
  template:
    metadata:
      labels:
        app: myapp
        version: green
    spec:
      containers:
      - name: app
        image: myapp:v2.0

---
# Service for Blue/Green switching
apiVersion: v1
kind: Service
metadata:
  name: app-service
spec:
  selector:
    app: myapp
    version: blue  # Switch to 'green' for cutover
  ports:
  - port: 80

---
# CANARY WITH ARGO ROLLOUTS
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: canary-rollout
spec:
  replicas: 10
  strategy:
    canary:
      steps:
      - setWeight: 10    # 10% traffic to canary
      - pause: {duration: 300}  # Wait 5 minutes
      - setWeight: 25    # 25% traffic
      - pause: {duration: 300}
      - setWeight: 50    # 50% traffic  
      - pause: {duration: 300}
      - setWeight: 100   # Full rollout
  selector:
    matchLabels:
      app: canary-app
  template:
    spec:
      containers:
      - name: app
        image: myapp:v2.0

---
# JOB - Run to completion
apiVersion: batch/v1
kind: Job
metadata:
  name: data-migration
spec:
  completions: 1      # Number of successful completions needed
  parallelism: 1      # Number of pods running in parallel
  backoffLimit: 3     # Number of retries before marking failed
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: migrator
        image: migrate:latest
        command: ["python", "migrate.py"]

---
# CRONJOB - Scheduled tasks
apiVersion: batch/v1
kind: CronJob
metadata:
  name: daily-backup
spec:
  schedule: "0 2 * * *"  # Every day at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: backup
            image: backup-tool:latest
            command: ["./backup.sh"]
  successfulJobsHistoryLimit: 3  # Keep last 3 successful jobs
  failedJobsHistoryLimit: 1      # Keep last failed job
```

</details>

<details>
<summary>📘 Click to see Workload Comparison Examples</summary>

```yaml
# DEPLOYMENT - Stateless web app
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1  # Can lose pods during update
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx

---
# STATEFULSET - Database cluster
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  serviceName: "mysql"
  replicas: 3
  podManagementPolicy: OrderedReady  # Sequential startup
  template:
    spec:
      containers:
      - name: mysql
        image: mysql:8.0
  volumeClaimTemplates:  # Each pod gets own storage
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi

---
# DAEMONSET - Monitoring agent
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
spec:
  selector:
    matchLabels:
      app: node-exporter
  template:
    spec:
      hostNetwork: true  # Access host metrics
      containers:
      - name: node-exporter
        image: prom/node-exporter
```

</details>

---

## 🌐 Networking Deep Dive - The "Why" Behind K8s Networking

### **The Networking Model Philosophy**

Kubernetes networking follows **three fundamental principles**:

1. **Every pod gets its own IP address** - No NAT between pods
2. **Pods can communicate with all other pods** - Without NAT
3. **Nodes can communicate with all pods** - Without NAT

**Why these principles?**
- **Simplifies application porting** - Apps work like on VMs
- **Removes port management complexity** - No port mapping needed
- **Enables service discovery** - Direct IP communication

### **Why Services Exist - The Problem They Solve**

**The Problem:**
- Pods are **ephemeral** - they come and go
- Pod IPs **change** when pods restart
- Applications need **stable endpoints**

**The Solution - Services:**
- Provide **stable DNS names and IPs**
- Implement **load balancing** across pods
- Enable **service discovery** within cluster

#### **Service Types Explained - When to Use Each**

| Type | **Why It Exists** | **Design Rationale** | **Use Case** |
|------|------------------|---------------------|--------------|
| **🏠 ClusterIP** | Internal communication only | Default, most secure, no external exposure | Databases, internal APIs |
| **🌐 NodePort** | Simple external access | Opens same port on all nodes, easy but limited | Development, simple demos |
| **⚖️ LoadBalancer** | Production external access | Integrates with cloud providers, gets real IP | Production web services |
| **🚪 ExternalName** | External service integration | DNS CNAME redirect, no proxying | External databases, APIs |

### **CNI (Container Network Interface) - Why Plugin Architecture?**

**Why not built-in networking?**
- **Different environments have different needs** - cloud vs on-prem vs edge
- **Performance vs features tradeoff** - overlay vs native
- **Vendor innovation** - allows best-of-breed solutions

**Popular CNI Plugins and Their Philosophy:**

| Plugin | **Design Philosophy** | **Why Choose It** |
|--------|---------------------|------------------|
| **Flannel** | Simple overlay network | Easy setup, good for learning |
| **Calico** | L3 routing, network policies | Performance, security features |
| **Weave** | Mesh network, encryption | Simple multicast, automatic discovery |
| **Cilium** | eBPF-based, API-aware | Advanced security, observability |

<details>
<summary>📘 Click to see Networking Examples</summary>

```yaml
# Service exposing deployment
apiVersion: v1
kind: Service
metadata:
  name: web-service
spec:
  type: ClusterIP  # Default, internal only
  selector:
    app: web  # Finds pods with this label
  ports:
  - port: 80        # Service port
    targetPort: 8080  # Pod port
    protocol: TCP

---
# Headless service for StatefulSet
apiVersion: v1
kind: Service
metadata:
  name: mysql-headless
spec:
  clusterIP: None  # Headless - no load balancing
  selector:
    app: mysql
  ports:
  - port: 3306

---
# NetworkPolicy for security
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-netpol
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

</details>

---

## 💾 Storage Management - Philosophy and Patterns

### **Why Storage Abstraction?**

Kubernetes abstracts storage through **PV/PVC model** because:

1. **Separation of concerns** - Admins provision storage, developers consume it
2. **Portability** - Same PVC works across different storage backends
3. **Dynamic provisioning** - Storage created on-demand
4. **Lifecycle management** - Storage can outlive pods

### **Storage Architecture Layers**

| Layer | **Purpose** | **Why This Design** |
|-------|------------|-------------------|
| **StorageClass** | Defines storage types | Abstracts backend differences |
| **PersistentVolume** | Actual storage resource | Admin-managed or dynamically created |
| **PersistentVolumeClaim** | Storage request | Developer-friendly abstraction |
| **Volume** | Pod mount point | Decouples storage from pod lifecycle |

### **Access Modes - Why Three Types?**

| Mode | **Abbreviation** | **Why It Exists** | **Use Case** |
|------|-----------------|------------------|--------------|
| **ReadWriteOnce** | RWO | Most storage supports single writer | Databases, single pod apps |
| **ReadOnlyMany** | ROX | Safe concurrent reads | Shared config, static content |
| **ReadWriteMany** | RWX | Requires special filesystem | Shared data, multi-pod writes |

**Why these limitations?**
- **Filesystem consistency** - Most filesystems can't handle concurrent writes
- **Performance** - Distributed filesystems (RWX) are slower
- **Cloud provider constraints** - AWS EBS is RWO only, need EFS for RWX

<details>
<summary>📘 Click to see Storage Examples</summary>

```yaml
# StorageClass with parameters
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3
  iops: "3000"
  encrypted: "true"
volumeBindingMode: WaitForFirstConsumer  # Delays until pod scheduled
reclaimPolicy: Delete  # What happens when PVC deleted
allowVolumeExpansion: true

---
# PVC requesting storage
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: app-storage
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd

---
# StatefulSet with volume template
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 20Gi
```

</details>

---

## 🔧 Resource Management - The Theory of Limits and Requests

### **Why Requests and Limits?**

Kubernetes uses **two-tier resource specification** because:

1. **Requests** = Guaranteed resources (scheduling decision)
2. **Limits** = Maximum allowed (prevents resource starvation)

**The Philosophy:**
- **Requests affect scheduling** - Pod only scheduled where resources available
- **Limits affect runtime** - Container killed/throttled if exceeds
- **Overcommit possible** - Sum of limits can exceed node capacity
- **QoS classes** - Determined by requests/limits configuration

### **Quality of Service (QoS) Classes**

| QoS Class | **Configuration** | **Why This Matters** | **Eviction Priority** |
|-----------|------------------|---------------------|---------------------|
| **Guaranteed** | Requests = Limits | Most stable, predictable performance | Last to be evicted |
| **Burstable** | Requests < Limits | Can use spare resources | Medium priority |
| **BestEffort** | No requests/limits | Uses whatever's available | First to be evicted |

**Why this hierarchy?**
- **Predictability for critical workloads** - Guaranteed class ensures performance
- **Efficient resource utilization** - Burstable allows using idle resources
- **Clear eviction order** - System knows what to kill under pressure

### **Resource Types Explained**

| Resource | **Unit** | **What Happens at Limit** | **Why Different Behavior** |
|----------|---------|-------------------------|--------------------------|
| **CPU** | millicores (m) | Throttled | CPU can be time-shared |
| **Memory** | bytes (Mi, Gi) | OOMKilled | Memory can't be compressed |
| **Ephemeral Storage** | bytes | Evicted | Protects node disk |

<details>
<summary>📘 Click to see Resource Management Examples</summary>

```yaml
# Guaranteed QoS (requests = limits)
apiVersion: v1
kind: Pod
metadata:
  name: guaranteed-pod
spec:
  containers:
  - name: app
    image: nginx
    resources:
      requests:
        memory: "1Gi"
        cpu: "500m"
      limits:
        memory: "1Gi"  # Same as request
        cpu: "500m"    # Same as request

---
# Burstable QoS (requests < limits)
apiVersion: v1
kind: Pod
metadata:
  name: burstable-pod
spec:
  containers:
  - name: app
    image: nginx
    resources:
      requests:
        memory: "500Mi"
        cpu: "250m"
      limits:
        memory: "1Gi"   # Can burst to 1Gi
        cpu: "500m"     # Can burst to 500m

---
# ResourceQuota for namespace
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: dev
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    persistentvolumeclaims: "5"
    
---
# LimitRange for defaults
apiVersion: v1
kind: LimitRange
metadata:
  name: mem-limit-range
  namespace: dev
spec:
  limits:
  - default:  # Default limits
      memory: 512Mi
      cpu: 500m
    defaultRequest:  # Default requests
      memory: 256Mi
      cpu: 100m
    type: Container
```

</details>

---

## 📈 Auto-scaling - Theory and Strategy

### **Why Three Types of Autoscaling?**

Kubernetes provides **three autoscaling dimensions** because different scenarios need different scaling approaches:

#### **HPA (Horizontal Pod Autoscaler) - Scale Out**

**Philosophy:**
- **Handles traffic spikes** by adding more pods
- **Stateless apps scale horizontally well**
- **Cost-effective** for variable loads

**How it decides:**
- Calculates: `desiredReplicas = ceil(currentReplicas * (currentMetric / targetMetric))`
- **Stabilization window** prevents flapping
- **Scale-down gradual** to prevent disruption

#### **VPA (Vertical Pod Autoscaler) - Scale Up**

**Philosophy:**
- **Right-sizing** pods based on actual usage
- **Stateful apps** that can't scale horizontally
- **Resource optimization** without code changes

**Why separate from HPA:**
- **Different scaling dimensions** - can't safely use both
- **Requires pod restart** for changes
- **Historical data analysis** for recommendations

#### **Cluster Autoscaler - Scale Infrastructure**

**Philosophy:**
- **Pods shouldn't fail due to lack of nodes**
- **Don't waste money on idle nodes**
- **Seamless scaling** without manual intervention

**Decision process:**
1. Pods pending due to insufficient resources → **Scale up**
2. Nodes underutilized for period → **Scale down**
3. Respects pod disruption budgets
4. Considers node drain timeouts

<details>
<summary>📘 Click to see Autoscaling Examples</summary>

```yaml
# HPA with multiple metrics
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50  # Scale down by max 50%
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100  # Can double pods
        periodSeconds: 60

---
# VPA configuration
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: web-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  updatePolicy:
    updateMode: "Auto"  # or "Off" for recommendations only
  resourcePolicy:
    containerPolicies:
    - containerName: app
      maxAllowed:
        cpu: 2
        memory: 2Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

</details>

---

## 🔍 Observability - Why Metrics, Logs, and Traces

### **The Three Pillars Theory**

**Why three different observability types?**

| Pillar | **What It Tells You** | **Why You Need It** | **Can't Replace With** |
|--------|---------------------|-------------------|---------------------|
| **📊 Metrics** | System health over time | Trends, capacity planning | Logs (too verbose) |
| **📝 Logs** | Detailed event information | Debugging, audit trail | Metrics (no context) |
| **🔗 Traces** | Request flow across services | Latency analysis, dependencies | Logs (no correlation) |

### **Prometheus + Grafana - Why This Stack?**

**Why Prometheus for Kubernetes:**
- **Pull-based model** - Services don't need to know about monitoring
- **Service discovery** - Automatically finds pods/services
- **PromQL** - Powerful query language for complex analysis
- **TSDB** - Efficient time-series storage

**Why Grafana:**
- **Multi-datasource** - Not locked to Prometheus
- **Templating** - Reusable dashboards
- **Alerting** - Visual alert configuration

<details>
<summary>📘 Click to see Observability Examples</summary>

```yaml
# ServiceMonitor for Prometheus
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: app-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: web-app
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics

---
# PrometheusRule for alerting
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: app-alerts
  namespace: monitoring
spec:
  groups:
  - name: app.rules
    interval: 30s
    rules:
    - alert: HighMemoryUsage
      expr: |
        (sum(rate(container_memory_usage_bytes[5m])) by (pod) 
         / sum(container_spec_memory_limit_bytes) by (pod)) > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Pod {{ $labels.pod }} high memory usage"
        description: "Memory usage above 90% for 5 minutes"
```

</details>

---

## 🎭 Advanced Patterns - Why These Patterns Evolved

### **Sidecar Pattern - Why It Exists**

**Problem it solves:**
- **Separation of concerns** - Main app shouldn't handle cross-cutting concerns
- **Language agnostic** - Sidecar can be in different language
- **Reusability** - Same sidecar across different apps

**Common sidecars:**
- **Proxy** (Envoy) - Service mesh, traffic management
- **Log shipper** (Fluentd) - Centralized logging
- **Monitoring** (Prometheus exporter) - Metrics collection

### **Operator Pattern - Why It's Powerful**

**Philosophy:**
- **Encode operational knowledge** in software
- **Extend Kubernetes API** with custom resources
- **Automated Day-2 operations** - backups, scaling, upgrades

**Why operators over helm charts:**
- **Active reconciliation** - Continuously ensures desired state
- **Domain-specific logic** - Understands application lifecycle
- **Stateful operations** - Can handle complex state transitions

### **GitOps - Why This Approach**

**Core principles:**
1. **Git as single source of truth**
2. **Declarative everything**
3. **Automated reconciliation**
4. **Observable deployment**

**Why GitOps works:**
- **Audit trail** - Every change tracked
- **Rollback** - Simple git revert
- **Review process** - PR/MR workflow
- **Disaster recovery** - Cluster rebuild from git

<details>
<summary>📘 Click to see Advanced Pattern Examples</summary>

```yaml
# Sidecar pattern with Envoy proxy
apiVersion: v1
kind: Pod
metadata:
  name: app-with-sidecar
spec:
  containers:
  - name: app
    image: myapp:latest
    ports:
    - containerPort: 8080
  - name: envoy-proxy
    image: envoyproxy/envoy:latest
    ports:
    - containerPort: 9901  # Admin
    - containerPort: 10000 # Proxy
    volumeMounts:
    - name: envoy-config
      mountPath: /etc/envoy
  volumes:
  - name: envoy-config
    configMap:
      name: envoy-config

---
# Custom Resource Definition for Operator
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: postgresqls.database.example.com
spec:
  group: database.example.com
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              version:
                type: string
              replicas:
                type: integer
              storage:
                type: string
  scope: Namespaced
  names:
    plural: postgresqls
    singular: postgresql
    kind: PostgreSQL

---
# GitOps with ArgoCD
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: production-app
  namespace: argocd
spec:
  source:
    repoURL: https://github.com/company/k8s-manifests
    targetRevision: main
    path: overlays/production
  destination:
    server: https://kubernetes.default.svc
  syncPolicy:
    automated:
      prune: true  # Delete resources not in git
      selfHeal: true  # Auto-sync when diverged
```

</details>

---

## 🎯 Production Best Practices - The "Why" Behind Each

### **Why These Specific Best Practices?**

| Practice | **Why It Matters** | **What Problems It Prevents** |
|----------|-------------------|------------------------------|
| **Resource limits** | Prevents noisy neighbor | Pod consuming all node resources |
| **Health checks** | Enables self-healing | Serving traffic to broken pods |
| **Pod Disruption Budgets** | Maintains availability | All replicas down during updates |
| **Network Policies** | Defense in depth | Lateral movement in breach |
| **RBAC** | Principle of least privilege | Unauthorized cluster access |
| **Namespaces** | Logical isolation | Resource conflicts, quotas |

### **High Availability Patterns**

**Why HA matters in Kubernetes:**
- **Node failures are expected** - Pets vs cattle mentality
- **Updates are frequent** - Monthly K8s releases
- **Cloud provider maintenance** - Planned and unplanned

**HA Strategies:**

| Component | **HA Pattern** | **Why This Way** |
|-----------|---------------|-----------------|
| **Control Plane** | 3+ masters, different AZs | Quorum for etcd, zone failure tolerance |
| **Worker Nodes** | Multiple node pools, different AZs | Workload distribution, zone failures |
| **Applications** | Multiple replicas, anti-affinity | Pod failures, node failures |
| **Storage** | Replicated storage, backups | Data durability |

<details>
<summary>📘 Click to see Production Best Practices Examples</summary>

```yaml
# PodDisruptionBudget
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-pdb
spec:
  minAvailable: 2  # Always keep 2 pods running
  selector:
    matchLabels:
      app: web

---
# Pod Anti-affinity for HA
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - web-app
            topologyKey: kubernetes.io/hostname  # Different nodes
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - web-app
              topologyKey: topology.kubernetes.io/zone  # Different zones

---
# Priority Classes for critical workloads
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: critical
value: 1000
globalDefault: false
description: "Critical production workloads"
```

</details>

---

## 🚨 Troubleshooting Philosophy

### **The Systematic Approach - Why This Order**

1. **Events first** - Recent cluster events show immediate issues
2. **Describe resources** - Detailed state and conditions
3. **Logs next** - Application-specific problems
4. **Resource metrics** - Performance issues
5. **Network tests** - Connectivity problems

**Why this sequence?**
- **Quick wins first** - Events often show the problem immediately
- **Narrow down systematically** - From cluster to pod to container
- **Avoid rabbit holes** - Don't debug app before checking basics

### **Common Issues - Why They Happen**

| Issue | **Root Cause** | **Why It's Common** | **Prevention** |
|-------|---------------|-------------------|----------------|
| **ImagePullBackOff** | Wrong image/no access | Typos, private registries | Image pull secrets, CI validation |
| **CrashLoopBackOff** | App crashes on start | Config issues, missing deps | Init containers, config validation |
| **Pending Pods** | No suitable nodes | Resource constraints | Cluster autoscaler, monitoring |
| **Failed Mounts** | Storage issues | PV/PVC mismatch, permissions | Storage classes, RBAC |

<details>
<summary>📘 Click to see Troubleshooting Commands</summary>

```bash
# Systematic debugging approach

# 1. Check events (cluster-wide issues)
kubectl get events --all-namespaces --sort-by='.lastTimestamp'

# 2. Describe pod (scheduling, image pulls)
kubectl describe pod <pod-name> -n <namespace>

# 3. Check logs (application issues)
kubectl logs <pod-name> -n <namespace> --previous  # Previous container
kubectl logs <pod-name> -n <namespace> -c <container>  # Specific container
kubectl logs -l app=web --all-containers=true  # All pods with label

# 4. Resource investigation
kubectl top nodes
kubectl top pods -n <namespace>
kubectl get pod <pod-name> -o yaml | grep -A10 resources:

# 5. Network debugging
kubectl exec -it <pod-name> -- nslookup kubernetes.default
kubectl exec -it <pod-name> -- wget -O- http://service:port
kubectl get endpoints <service-name>

# 6. Node issues
kubectl get nodes
kubectl describe node <node-name>
kubectl get node <node-name> -o yaml | grep -i taint

# 7. RBAC issues
kubectl auth can-i create pods --as=system:serviceaccount:default:default
kubectl get rolebindings,clusterrolebindings -A | grep <serviceaccount>
```

</details>

---

## ⚡ Interview Success Strategies

### **How to Approach K8s Interview Questions**

1. **Start with the "Why"** - Explain the problem being solved
2. **Mention tradeoffs** - Every solution has pros/cons
3. **Give real examples** - From your experience
4. **Consider scale** - Solutions differ at different scales
5. **Security and cost** - Always mention these aspects

### **Key Topics to Master**

| Topic | **What Interviewers Look For** | **Red Flags** |
|-------|-------------------------------|---------------|
| **Architecture** | Understanding of distributed systems | Memorized without understanding |
| **Networking** | Troubleshooting approach, CNI knowledge | Only knowing kubectl expose |
| **Storage** | StatefulSet patterns, data persistence | Not knowing PV/PVC relationship |
| **Security** | RBAC, network policies, secrets | Storing secrets in configmaps |
| **Scaling** | HPA, VPA, cluster autoscaler | Manual scaling only |
| **Monitoring** | Metrics, logs, traces understanding | No production monitoring experience |

---

> 💡 **Pro Interview Tip**: Always explain your reasoning. Interviewers want to understand HOW you think, not just WHAT you know. When discussing solutions, mention: Why this approach? What are alternatives? What are the tradeoffs? How would you monitor/troubleshoot it?

---

**🎯 Key Takeaway:**
Kubernetes is built on solid distributed systems principles. Understanding the "why" behind each component and pattern makes you a stronger engineer than just knowing commands and YAML syntax. Focus on the problems Kubernetes solves and why it solves them in specific ways.