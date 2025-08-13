# 🛡️ Kubernetes Security - Interview Deep Dive Guide

> **🔐 Master K8s Security for Senior DevOps Roles** - Deep security theory and practice

---

## 🎯 Security Fundamentals - The Theory Behind Defense in Depth

### **Why Security Layers Matter**

Kubernetes security operates on the principle that **no single security control is sufficient**. Each layer provides **defense against different attack vectors**:

- **🏗️ Infrastructure Layer** - Protects against node compromises and network attacks
- **🎛️ Control Plane Layer** - Secures cluster management and configuration
- **🧩 Workload Layer** - Isolates applications from each other and the host
- **📦 Container Layer** - Prevents malicious code execution
- **🌐 Network Layer** - Controls communication between components
- **💾 Data Layer** - Protects sensitive information at rest and in transit

### **Security Design Philosophy**

| Principle | **What It Means** | **Why It's Critical** |
|-----------|------------------|----------------------|
| **Zero Trust** | Never trust, always verify | Assume breaches will happen |
| **Least Privilege** | Minimum permissions needed | Reduces blast radius |
| **Defense in Depth** | Multiple security layers | No single point of failure |
| **Fail Secure** | Deny by default | Safe failure modes |
| **Principle of Segregation** | Separate duties and access | Prevents insider threats |

<details>
<summary>📘 Click to see Defense in Depth Implementation</summary>

```yaml
# Example showing multiple security layers
apiVersion: v1
kind: Namespace
metadata:
  name: secure-app
  labels:
    # Pod Security Standards - Layer 1
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    
    # Network segmentation - Layer 2
    network-policy: enabled

---
# Network Policy - Layer 3
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: secure-app
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  # Deny all traffic by default

---
# RBAC - Layer 4
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: secure-app
  name: app-operator
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "update", "patch"]

---
# Secure Deployment - Layer 5
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: secure-app
spec:
  template:
    spec:
      securityContext:  # Pod security context
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myapp:v1.0-distroless  # Minimal image
        securityContext:  # Container security context
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
        resources:  # Resource limits
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
```

</details>

---

## 🔐 Authentication & Authorization - Identity and Access Theory

### **Why Kubernetes Has Multiple Auth Mechanisms**

Kubernetes supports multiple authentication methods because different environments have different needs:

- **Service Accounts** - For pod-to-API server communication
- **User Accounts** - For human users (external identity providers)
- **Bootstrap Tokens** - For initial cluster setup
- **Client Certificates** - For system components and admin access

### **Authentication vs Authorization**

| **Authentication** | **Authorization** |
|-------------------|------------------|
| **Who are you?** | **What can you do?** |
| Identity verification | Permission checking |
| X.509 certificates, tokens | RBAC, ABAC, webhooks |
| Happens first | Happens after auth |

### **Service Account Deep Dive**

**Why Service Accounts exist:**
- **Pod identity** - Each pod needs an identity to call the API
- **Automated systems** - Controllers, operators need permissions
- **Namespace isolation** - Service accounts are namespaced
- **Token management** - Kubernetes handles token lifecycle

**Service Account Token Evolution:**
- **v1.20 and earlier** - Long-lived tokens stored in secrets
- **v1.21+** - Short-lived tokens bound to pods (BoundServiceAccountTokenVolume)
- **v1.24+** - LegacyServiceAccountTokenNoAutoGeneration (manual secret creation needed)

<details>
<summary>📘 Click to see Service Account Examples</summary>

```yaml
# Service Account with minimal permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitoring-sa
  namespace: monitoring
automountServiceAccountToken: false  # Security: explicit control

---
# Pod explicitly using service account
apiVersion: v1
kind: Pod
metadata:
  name: monitoring-pod
  namespace: monitoring
spec:
  serviceAccountName: monitoring-sa
  automountServiceAccountToken: true
  containers:
  - name: monitor
    image: prometheus:latest
    volumeMounts:
    - name: kube-api-access
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      readOnly: true
  volumes:
  - name: kube-api-access
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600  # 1 hour token
      - configMap:
          name: kube-root-ca.crt
          items:
          - key: ca.crt
            path: ca.crt
      - downwardAPI:
          items:
          - path: namespace
            fieldRef:
              fieldPath: metadata.namespace

---
# Legacy service account secret (for older clusters)
apiVersion: v1
kind: Secret
metadata:
  name: monitoring-sa-token
  namespace: monitoring
  annotations:
    kubernetes.io/service-account.name: monitoring-sa
type: kubernetes.io/service-account-token
```

</details>

### **RBAC (Role-Based Access Control) Theory**

**Why RBAC over ABAC:**
- **Simpler to understand** - Role-based is more intuitive
- **Easier to audit** - Clear role definitions
- **Better tooling** - kubectl can show effective permissions
- **Namespace support** - Roles can be namespaced or cluster-wide

**RBAC Components Explained:**

| Component | **Scope** | **Purpose** | **Contains** |
|-----------|-----------|-------------|--------------|
| **Role** | Namespace | Define permissions | Rules (apiGroups, resources, verbs) |
| **ClusterRole** | Cluster-wide | Define permissions | Rules + cluster resources |
| **RoleBinding** | Namespace | Grant permissions | Subject + Role reference |
| **ClusterRoleBinding** | Cluster-wide | Grant permissions | Subject + ClusterRole reference |

### **Advanced RBAC Patterns**

#### **Aggregated ClusterRoles**
**Philosophy:** Build complex roles from simple components
- **Composition over inheritance** - Combine smaller roles
- **Maintainability** - Change component roles without touching aggregates
- **Flexibility** - Different combinations for different needs

#### **RBAC with External Identity**
**Integration patterns:**
- **OIDC Integration** - Google, Azure AD, Auth0
- **Webhook Authentication** - Custom identity providers
- **Certificate-based** - X.509 client certificates

<details>
<summary>📘 Click to see Advanced RBAC Examples</summary>

```yaml
# Aggregated ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-aggregated
aggregationRule:
  clusterRoleSelectors:
  - matchLabels:
      rbac.example.com/aggregate-to-monitoring: "true"
rules: []  # Rules will be automatically filled

---
# Component role for pod access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitor-pods
  labels:
    rbac.example.com/aggregate-to-monitoring: "true"
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]

---
# Component role for metrics access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitor-metrics
  labels:
    rbac.example.com/aggregate-to-monitoring: "true"
rules:
- apiGroups: ["metrics.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list"]

---
# Conditional access based on resource names
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: specific-pod-access
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
  resourceNames: ["web-pod-1", "web-pod-2"]  # Only specific pods

---
# Cross-namespace access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cross-namespace-reader
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
  # This ClusterRole allows reading ConfigMaps in any namespace

---
# Binding to external groups (OIDC)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: platform-team-binding
subjects:
- kind: Group
  name: platform-engineers@company.com  # From OIDC provider
  apiGroup: rbac.authorization.k8s.io
- kind: User
  name: service-account@company.iam.gserviceaccount.com  # Google service account
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io

---
# Time-bound access (requires external tooling)
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: temp-debug-access
  namespace: production
  annotations:
    expires-at: "2024-01-15T10:00:00Z"  # Custom annotation for external cleanup
subjects:
- kind: User
  name: debug-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: debug-role
  apiGroup: rbac.authorization.k8s.io
```

</details>

---

## 🚪 Admission Controllers - The Gateway Guardians

### **Why Admission Controllers Are Critical**

Admission controllers are the **last line of defense** before objects are persisted to etcd:

- **Validating controllers** - Reject invalid configurations
- **Mutating controllers** - Modify objects to add security defaults
- **Policy enforcement** - Ensure compliance with organizational policies
- **Security injection** - Add security contexts, sidecars, etc.

### **Types of Admission Controllers**

| Type | **When It Runs** | **What It Does** | **Example** |
|------|-----------------|------------------|-------------|
| **Validating** | After mutation | Accept/reject requests | ValidatingAdmissionWebhook |
| **Mutating** | Before validation | Modify objects | MutatingAdmissionWebhook |
| **Built-in** | During admission | Enforce built-in policies | PodSecurity, ResourceQuota |

### **Pod Security Standards (PSS) - The New Security Model**

**Why PSS replaced Pod Security Policies:**
- **Simpler to use** - Three predefined profiles instead of complex policies
- **Better defaults** - Progressively restrictive security posture
- **Built-in** - No need for external admission controllers
- **Namespace-scoped** - Easier to manage than cluster-wide PSPs

**Security Profiles Explained:**

| Profile | **Philosophy** | **Use Case** | **Key Restrictions** |
|---------|---------------|--------------|---------------------|
| **Privileged** | Unrestricted | System components | None - allows everything |
| **Baseline** | Minimally restrictive | Standard applications | No privileged, hostNetwork, dangerous capabilities |
| **Restricted** | Heavily restricted | Security-critical apps | + non-root user, read-only filesystem, dropped capabilities |

### **Custom Admission Controllers**

**Common patterns:**
- **Policy-as-Code** - OPA Gatekeeper for complex policies
- **Security injection** - Automatically add security sidecars
- **Compliance enforcement** - Ensure all pods meet regulatory requirements
- **Resource manipulation** - Add monitoring, backup annotations

<details>
<summary>📘 Click to see Admission Controller Examples</summary>

```yaml
# Pod Security Standards namespace configuration
apiVersion: v1
kind: Namespace
metadata:
  name: restricted-apps
  labels:
    # Enforce restricted profile
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    
    # Audit against baseline (less restrictive)
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/audit-version: v1.28
    
    # Warn when violating baseline
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/warn-version: v1.28

---
# ValidatingAdmissionWebhook example
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: security-policy-webhook
webhooks:
- name: pod-security.company.com
  clientConfig:
    service:
      name: security-webhook
      namespace: security-system
      path: /validate
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Fail  # Fail closed for security

---
# MutatingAdmissionWebhook for security injection
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionWebhook
metadata:
  name: security-defaults-webhook
webhooks:
- name: defaults.security.company.com
  clientConfig:
    service:
      name: security-webhook
      namespace: security-system
      path: /mutate
  rules:
  - operations: ["CREATE"]
    apiGroups: ["apps"]
    apiVersions: ["v1"]
    resources: ["deployments"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  failurePolicy: Fail

---
# OPA Gatekeeper ConstraintTemplate
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSecurityContext
      validation:
        type: object
        properties:
          runAsNonRoot:
            type: boolean
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredsecuritycontext

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.securityContext.runAsNonRoot == true
          msg := sprintf("Container %v must run as non-root user", [container.name])
        }

---
# Gatekeeper Constraint using the template
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredSecurityContext
metadata:
  name: must-run-as-non-root
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
    namespaces: ["production", "staging"]
  parameters:
    runAsNonRoot: true

---
# Example of automatic sidecar injection
# This would be handled by a mutating webhook
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-auto-sidecar
  annotations:
    sidecar.security.company.com/inject: "true"
spec:
  template:
    spec:
      containers:
      - name: main-app
        image: myapp:latest
      # Sidecar would be automatically injected here by webhook:
      # - name: security-agent
      #   image: security-agent:latest
      #   securityContext:
      #     privileged: false
```

</details>

---

## 🌐 Network Security - Microsegmentation Theory

### **Why Network Policies Are Essential**

**Default Kubernetes networking** is **flat and permissive**:
- All pods can communicate with all other pods
- All pods can reach external networks
- No traffic inspection or filtering

**Network policies implement:**
- **Zero-trust networking** - deny by default, allow explicitly
- **Microsegmentation** - isolate workloads from each other
- **Traffic control** - ingress and egress rules
- **Namespace isolation** - prevent cross-namespace communication

### **Network Policy Philosophy**

**Design principles:**
- **Additive model** - Multiple policies can apply to same pod
- **Deny by default** - Empty policy blocks all traffic
- **Label selectors** - Dynamic selection based on labels
- **Namespace boundaries** - Policies are namespace-scoped

### **Common Network Security Patterns**

#### **Default Deny Pattern**
**Philosophy:** Start with no access, add permissions as needed
- **Security first** - Prevents unknown communication paths
- **Explicit permissions** - Every connection must be intentional
- **Easier compliance** - Clear audit trail of allowed communications

#### **Tier-based Segmentation**
**Philosophy:** Group similar services and control inter-tier communication
- **Frontend tier** - Web servers, API gateways
- **Application tier** - Business logic, microservices
- **Data tier** - Databases, caches
- **Infrastructure tier** - Monitoring, logging

<details>
<summary>📘 Click to see Network Policy Examples</summary>

```yaml
# Default deny all ingress and egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Allow ingress from specific namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-frontend
  namespace: backend
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: frontend
    - podSelector:  # AND condition with namespace
        matchLabels:
          role: api-gateway
    ports:
    - protocol: TCP
      port: 8080

---
# Allow egress to external services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-apis
  namespace: backend
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
  - Egress
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow HTTPS to external payment API
  - to: []
    ports:
    - protocol: TCP
      port: 443
  # Allow access to internal database
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432

---
# Multi-tier application with network segmentation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-tier-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      tier: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow traffic from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
  egress:
  # Allow DNS
  - to: []
    ports:
    - protocol: UDP
      port: 53
  # Allow access to API tier
  - to:
    - podSelector:
        matchLabels:
          tier: api
    ports:
    - protocol: TCP
      port: 8080

---
# API tier policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-tier-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow from web tier
  - from:
    - podSelector:
        matchLabels:
          tier: web
    ports:
    - protocol: TCP
      port: 8080
  egress:
  # Allow DNS
  - to: []
    ports:
    - protocol: UDP
      port: 53
  # Allow access to data tier
  - to:
    - podSelector:
        matchLabels:
          tier: data
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 6379  # Redis

---
# Data tier policy (most restrictive)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: data-tier-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      tier: data
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Only allow from API tier
  - from:
    - podSelector:
        matchLabels:
          tier: api
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 6379
  egress:
  # Allow DNS only
  - to: []
    ports:
    - protocol: UDP
      port: 53

---
# Advanced: Time-based access (using labels and external controller)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: business-hours-access
  namespace: finance
  annotations:
    policy.network.company.com/schedule: "0 9 * * 1-5"  # 9 AM weekdays
    policy.network.company.com/timezone: "UTC"
spec:
  podSelector:
    matchLabels:
      app: financial-reports
      access-time: business-hours  # Label managed by external controller
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: analyst
    ports:
    - protocol: TCP
      port: 8080
```

</details>

---

## 🔐 Container and Pod Security - Runtime Protection

### **Why Container Security Contexts Matter**

**Without security contexts:**
- Containers run as **root by default** (UID 0)
- **Full filesystem access** - can modify host files
- **All Linux capabilities** - can perform privileged operations
- **Shared namespaces** - can see other processes, network

**With proper security contexts:**
- **Non-root execution** - limited privilege escalation
- **Read-only filesystems** - prevent malicious file writes
- **Capability dropping** - remove dangerous permissions
- **Resource limits** - prevent resource exhaustion

### **Security Context Hierarchy**

**Pod-level security context** applies to all containers unless overridden
**Container-level security context** overrides pod settings for that container

| Setting | **Pod Level** | **Container Level** | **Which Wins** |
|---------|--------------|-------------------|----------------|
| runAsUser | ✅ | ✅ | Container |
| runAsGroup | ✅ | ✅ | Container |
| fsGroup | ✅ | ❌ | Pod only |
| seccompProfile | ✅ | ✅ | Container |
| capabilities | ❌ | ✅ | Container only |

### **Linux Capabilities Deep Dive**

**Why capabilities matter:**
- Traditional Unix has **binary privilege model** - root or user
- Capabilities provide **fine-grained privileges**
- Drop dangerous capabilities, keep only necessary ones

**Common dangerous capabilities:**
- **SYS_ADMIN** - Mount filesystems, change namespaces
- **NET_ADMIN** - Network configuration
- **SYS_PTRACE** - Debug other processes
- **DAC_OVERRIDE** - Bypass file permissions

<details>
<summary>📘 Click to see Container Security Examples</summary>

```yaml
# Maximum security hardening
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    # seccompProfile applies to all containers
    seccompProfile:
      type: RuntimeDefault
    # sysctls for network security
    sysctls:
    - name: net.ipv4.ip_forward
      value: "0"
    - name: net.ipv4.conf.all.forwarding
      value: "0"

  containers:
  - name: secure-app
    image: myapp:latest
    
    # Container-level security (overrides pod settings)
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 3000
      # Read-only root filesystem
      readOnlyRootFilesystem: true
      # Prevent privilege escalation
      allowPrivilegeEscalation: false
      # Drop all capabilities, add only what's needed
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # Only if needed to bind to port < 1024
      # SELinux/AppArmor profile
      seLinuxOptions:
        level: "s0:c123,c456"
      # Seccomp profile for syscall filtering
      seccompProfile:
        type: Localhost
        localhostProfile: profiles/strict.json
    
    # Resource limits prevent DoS
    resources:
      requests:
        memory: "64Mi"
        cpu: "100m"
        ephemeral-storage: "1Gi"
      limits:
        memory: "128Mi"
        cpu: "200m"
        ephemeral-storage: "2Gi"
    
    # Mount writable directories as tmpfs
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: var-run
      mountPath: /var/run
    - name: app-cache
      mountPath: /app/cache
    
    # Environment variables (avoid secrets here)
    env:
    - name: APP_MODE
      value: "production"
    - name: LOG_LEVEL
      value: "info"
    
    # Health checks for reliability
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
        scheme: HTTP
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 3
      failureThreshold: 3

  volumes:
  - name: tmp
    emptyDir: {}
  - name: var-run
    emptyDir: {}
  - name: app-cache
    emptyDir:
      sizeLimit: 100Mi

  # Pod-level network settings
  dnsPolicy: ClusterFirst
  # Disable service account token auto-mount
  automountServiceAccountToken: false
  
  # Node selection and affinity
  nodeSelector:
    security.company.com/hardened: "true"
  
  # Priority for important workloads
  priorityClassName: high-priority
  
  # Pod disruption budget reference
  # (defined separately)

---
# AppArmor profile example (would be loaded on nodes)
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/secure-app: localhost/k8s-strict
spec:
  containers:
  - name: secure-app
    image: myapp:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000

---
# Seccomp profile example
apiVersion: v1
kind: ConfigMap
metadata:
  name: seccomp-profile
data:
  strict.json: |
    {
      "defaultAction": "SCMP_ACT_ERRNO",
      "architectures": ["SCMP_ARCH_X86_64"],
      "syscalls": [
        {
          "names": [
            "read", "write", "open", "close", "stat", "fstat", "lstat",
            "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "ioctl",
            "access", "pipe", "select", "sched_yield", "mremap", "msync",
            "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2",
            "pause", "nanosleep", "alarm", "getpid", "socket", "connect",
            "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
            "bind", "listen", "getsockname", "getpeername", "socketpair",
            "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
            "exit", "wait4", "kill", "uname", "semget", "semop", "semctl",
            "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock",
            "fsync", "fdatasync", "truncate", "ftruncate", "getdents",
            "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir",
            "creat", "link", "unlink", "symlink", "readlink", "chmod",
            "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday",
            "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid",
            "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid",
            "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid",
            "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
            "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid",
            "capget", "capset", "rt_sigpending", "rt_sigtimedwait",
            "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime",
            "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs",
            "sysfs", "getpriority", "setpriority", "sched_setparam",
            "sched_getparam", "sched_setscheduler", "sched_getscheduler",
            "sched_get_priority_max", "sched_get_priority_min",
            "sched_rr_get_interval", "mlock", "munlock", "mlockall",
            "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl",
            "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync",
            "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff",
            "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
            "create_module", "init_module", "delete_module", "get_kernel_syms",
            "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg",
            "afs_syscall", "tuxcall", "security", "gettid", "readahead",
            "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr",
            "fgetxattr", "listxattr", "llistxattr", "flistxattr",
            "removexattr", "lremovexattr", "fremovexattr", "tkill",
            "time", "futex", "sched_setaffinity", "sched_getaffinity",
            "set_thread_area", "io_setup", "io_destroy", "io_getevents",
            "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie",
            "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages",
            "getdents64", "set_tid_address", "restart_syscall", "semtimedop",
            "fadvise64", "timer_create", "timer_settime", "timer_gettime",
            "timer_getoverrun", "timer_delete", "clock_settime",
            "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
            "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver",
            "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink",
            "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr",
            "kexec_load", "waitid", "add_key", "request_key", "keyctl",
            "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
            "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
            "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
            "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat",
            "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list",
            "get_robust_list", "splice", "tee", "sync_file_range",
            "vmsplice", "move_pages", "utimensat", "epoll_pwait",
            "signalfd", "timerfd_create", "eventfd", "fallocate",
            "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4",
            "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1",
            "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open"
          ],
          "action": "SCMP_ACT_ALLOW"
        }
      ]
    }
```

</details>

---

## 🔑 Secrets Management - Protecting Sensitive Data

### **Why Kubernetes Secrets Aren't Enough**

**Built-in Kubernetes Secrets limitations:**
- **Base64 encoded, not encrypted** - Easy to decode
- **Stored in etcd** - Single point of compromise
- **No rotation** - Manual process for updates
- **No audit trail** - Hard to track access
- **Namespace scoped** - Can't easily share across namespaces

### **External Secrets Management Philosophy**

**Why external secret stores:**
- **Centralized management** - Single source of truth
- **Automatic rotation** - Reduces credential exposure
- **Fine-grained access** - Per-secret permissions
- **Audit logging** - Full access trails
- **Encryption at rest** - Proper cryptographic storage

### **Secret Injection Patterns**

| Pattern | **How It Works** | **Pros** | **Cons** |
|---------|-----------------|----------|----------|
| **Volume mount** | Mount secret as file | Standard, works everywhere | File system access needed |
| **Environment variable** | Inject as env var | Simple, widely supported | Visible in process list |
| **Init container** | Fetch before main container | Flexible, custom logic | Additional complexity |
| **CSI driver** | External system mounts | Automatic, transparent | Requires CSI support |
| **Sidecar** | Proxy/agent pattern | Real-time updates | Resource overhead |

<details>
<summary>📘 Click to see Secrets Management Examples</summary>

```yaml
# External Secrets Operator with AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: production
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa

---
# External Secret definition
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-database-secret
  namespace: production
spec:
  refreshInterval: 1h  # Refresh every hour
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: database-credentials
    creationPolicy: Owner
    template:
      type: Opaque
      data:
        # Template the data from external source
        username: "{{ .username }}"
        password: "{{ .password }}"
        host: "{{ .host }}"
        port: "{{ .port }}"
        # Computed value
        connection_string: "postgresql://{{ .username }}:{{ .password }}@{{ .host }}:{{ .port }}/{{ .database }}"
  data:
  - secretKey: username
    remoteRef:
      key: production/database
      property: username
  - secretKey: password
    remoteRef:
      key: production/database
      property: password
  - secretKey: host
    remoteRef:
      key: production/database
      property: host
  - secretKey: port
    remoteRef:
      key: production/database
      property: port
  - secretKey: database
    remoteRef:
      key: production/database
      property: database

---
# HashiCorp Vault integration
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "production-role"
          serviceAccountRef:
            name: vault-auth-sa

---
# Vault secret with automatic rotation
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-dynamic-secret
  namespace: production
spec:
  refreshInterval: 15m  # Rotate every 15 minutes
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: dynamic-db-credentials
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: database/creds/readonly
      property: username
  - secretKey: password
    remoteRef:
      key: database/creds/readonly
      property: password

---
# Secrets CSI Driver (alternative approach)
apiVersion: v1
kind: SecretProviderClass
metadata:
  name: app-secrets-csi
  namespace: production
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "production/app-config"
        objectType: "secretsmanager"
        jmesPath:
          - path: "database.username"
            objectAlias: "db-username"
          - path: "database.password"
            objectAlias: "db-password"
          - path: "api.key"
            objectAlias: "api-key"

---
# Pod using CSI-mounted secrets
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-csi-secrets
spec:
  template:
    spec:
      serviceAccountName: app-service-account
      containers:
      - name: app
        image: myapp:latest
        volumeMounts:
        - name: secrets-store
          mountPath: "/mnt/secrets-store"
          readOnly: true
        env:
        - name: DB_USERNAME_FILE
          value: "/mnt/secrets-store/db-username"
        - name: DB_PASSWORD_FILE
          value: "/mnt/secrets-store/db-password"
      volumes:
      - name: secrets-store
        csi:
          driver: secrets-store.csi.k8s.io
          readOnly: true
          volumeAttributes:
            secretProviderClass: "app-secrets-csi"

---
# Secure secret handling in application
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  # Non-sensitive configuration
  log_level: "info"
  feature_flags: "new-ui,metrics"
  # Reference to secret, not the secret itself
  database_credentials_path: "/etc/secrets/database"
  api_key_path: "/etc/secrets/api-key"

---
# Best practice: Separate secrets by purpose
apiVersion: v1
kind: Secret
metadata:
  name: database-readonly-credentials
  namespace: production
  labels:
    app: myapp
    purpose: database-access
    access-level: readonly
type: Opaque
data:
  username: <base64-encoded>
  password: <base64-encoded>

---
apiVersion: v1
kind: Secret
metadata:
  name: api-keys
  namespace: production
  labels:
    app: myapp
    purpose: external-api
type: Opaque
data:
  payment-gateway: <base64-encoded>
  notification-service: <base64-encoded>

---
# Secret rotation job (external controller pattern)
apiVersion: batch/v1
kind: CronJob
metadata:
  name: secret-rotation-job
  namespace: security-system
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: secret-rotator
          containers:
          - name: rotator
            image: secret-rotator:latest
            env:
            - name: TARGET_NAMESPACE
              value: "production"
            - name: SECRET_STORE_URL
              value: "https://vault.company.com"
            command:
            - /bin/rotate-secrets
            - --namespace=$(TARGET_NAMESPACE)
            - --vault-url=$(SECRET_STORE_URL)
          restartPolicy: OnFailure
```

</details>

---

## 🎯 Security Interview Success Strategy

### **How to Approach Security Questions**

1. **Start with threat model** - What attacks are we defending against?
2. **Explain defense in depth** - Multiple layers of protection
3. **Mention compliance** - How security enables business requirements
4. **Give real examples** - Concrete scenarios from your experience
5. **Consider operational impact** - Balance security with usability

### **Common Security Interview Questions**

| Question Type | **What Interviewers Want** | **How to Answer** |
|---------------|---------------------------|-------------------|
| **"How do you secure a K8s cluster?"** | Systematic security approach | Walk through each layer of defense |
| **"Explain RBAC"** | Understanding of access control | Start with principles, then examples |
| **"What are network policies?"** | Zero-trust networking knowledge | Default-deny concept, microsegmentation |
| **"How do you handle secrets?"** | External secrets management | Problems with K8s secrets, external solutions |
| **"Container security best practices"** | Runtime security knowledge | Non-root, read-only FS, capability dropping |

### **Security Red Flags to Avoid**

- **"Security slows us down"** - Shows wrong mindset
- **"Default configurations are fine"** - Lacks security awareness  
- **"We use RBAC"** without explaining principles
- **"Network policies are complex"** - Avoiding important security control
- **Storing secrets in ConfigMaps** - Basic security mistake

---

> 💡 **Security Interview Success Tip**: Always explain the "why" behind security controls. Show you understand the threats you're defending against and can balance security with operational needs. Demonstrate that security is an enabler, not a blocker.

---

**🎯 Key Security Takeaway:**
Kubernetes security is about implementing defense in depth - multiple layers of protection that work together. Understanding the threat model and applying appropriate controls at each layer demonstrates senior-level security thinking.