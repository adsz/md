# ☁️ Amazon EKS - Senior DevOps Engineer Knowledge Base

> **🎯 AWS-Specific K8s Interview Prep** - Master EKS for senior cloud roles

---

## 🏗️ EKS Architecture Deep Dive

### **Why EKS Exists - The Problem It Solves**

Before EKS, running Kubernetes on AWS meant:
- **Manual control plane management** - Installing, upgrading, patching masters
- **Complex HA setup** - Multi-master configuration across AZs  
- **No AWS service integration** - Manual setup for load balancers, storage
- **Operations overhead** - etcd backups, certificate management

**EKS solves this by:**
- **Fully managed control plane** - AWS handles masters, etcd, API server
- **AWS-native integrations** - IAM, VPC, ELB, EBS work out of the box
- **High availability by default** - Multi-AZ masters automatically
- **Automatic updates** - Control plane patches without downtime

### 🧠 Control Plane vs Data Plane - Shared Responsibility

| Component | **Managed By** | **Why This Split** | **Your Responsibilities** |
|-----------|---------------|-------------------|-------------------------|
| **🎛️ API Server** | AWS | Security, HA, scaling | Authentication, authorization (IAM/RBAC) |
| **⚡ etcd** | AWS | Backups, encryption, HA | Cluster resource management |
| **📋 Scheduler** | AWS | Optimal placement logic | Node labels, taints, affinity rules |
| **🔧 Worker Nodes** | Customer | Cost control, customization | Patching, scaling, instance types |
| **🌐 VPC CNI** | Customer | Network control | IP allocation, security groups |

**Why this separation?**
- **AWS expertise** in running distributed systems at scale
- **Customer control** over cost and workload placement
- **Compliance boundaries** - customer data stays in customer VPC
- **Flexibility** - choice of node types, AMIs, networking

### 🔗 EKS Cluster Endpoint Access Patterns

#### **Public Endpoint - Development/Simple Setups**
**Philosophy:** Easy access for development, CI/CD systems
**Security considerations:** Restricted CIDR blocks, VPN access

#### **Private Endpoint - Production Security**
**Philosophy:** Zero internet exposure, VPC-only access
**Considerations:** Requires VPN/Direct Connect, bastion hosts

#### **Mixed Mode - Balanced Approach**
**Philosophy:** Private for workloads, public for CI/CD (restricted)
**Best practice:** Most common production pattern

<details>
<summary>📘 Click to see Endpoint Configuration Examples</summary>

```yaml
# Public + Private (Mixed) - Most Common
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: production-cluster
clusterEndpoint:
  privateAccess: true   # VPC access for nodes
  publicAccess: true    # Internet access for CI/CD
  publicAccessCidrs:    # Restrict public access
    - "203.0.113.0/24"  # Office IP range
    - "198.51.100.0/24" # CI/CD system IPs

---
# Private Only - Maximum Security
clusterEndpoint:
  privateAccess: true
  publicAccess: false
  # Requires: VPN, Direct Connect, or bastion hosts

---
# Public Only - Development/Demo
clusterEndpoint:
  privateAccess: false
  publicAccess: true
  publicAccessCidrs:
    - "0.0.0.0/0"  # Open to internet (NOT recommended for prod)
```

</details>

---

## 🚀 Node Groups Deep Dive - Compute Strategy

### **Why Three Node Types?**

Each node type serves different operational models:

#### **🤖 Managed Node Groups - Production Workhorse**

**Design Philosophy:**
- **AWS handles node lifecycle** - patching, scaling, updates
- **Integration with AWS services** - Auto Scaling, Launch Templates
- **Simplified operations** - less operational overhead

**Why choose Managed:**
- **Production workloads** requiring predictable performance
- **Teams wanting less infrastructure management**
- **Need for custom instance types and AMIs** (with launch templates)
- **Cost optimization** through Spot instances

#### **⚙️ Self-managed Nodes - Maximum Control**

**Design Philosophy:**
- **Full control over node configuration** - custom AMIs, bootstrap scripts
- **Advanced networking** - custom CNI, security tools
- **Compliance requirements** - specific hardening, agents

**Why choose Self-managed:**
- **Highly regulated environments** requiring custom configurations
- **Special software** requiring specific OS configurations
- **Advanced networking** needs beyond VPC CNI
- **Migration from existing infrastructure**

#### **🏃 Fargate - Serverless Pods**

**Design Philosophy:**
- **Pod-level isolation** - each pod in separate compute environment
- **No node management** - AWS handles all infrastructure
- **Pay-per-pod** pricing model

**Why choose Fargate:**
- **Batch processing** jobs with varying resource needs
- **CI/CD workloads** that spike unpredictably
- **Security-sensitive workloads** needing isolation
- **Teams wanting zero infrastructure management**

### **Node Group Scaling Strategies**

#### **Cluster Autoscaler Pattern**
- **Reactive scaling** - responds to pending pods
- **Node group aware** - can scale different node types
- **Cost-conscious** - prefers cheaper nodes when possible

#### **Predictive Scaling**
- **Scheduled scaling** for known traffic patterns
- **Pre-warming** nodes before traffic spikes
- **Business calendar integration** for planned events

<details>
<summary>📘 Click to see Node Group Configuration Examples</summary>

```yaml
# MANAGED NODE GROUP - Production Setup
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: production-cluster
  region: us-west-2

managedNodeGroups:
  # System services node group
  - name: system-nodes
    instanceTypes: ["t3.medium"]
    minSize: 2
    maxSize: 4
    desiredCapacity: 2
    
    # Dedicated for system workloads
    labels:
      node-role: system
    taints:
      - key: CriticalAddonsOnly
        value: "true"
        effect: NoSchedule
    
    # Mixed instance policy for cost optimization
    spot: false  # On-demand for system stability
    
    # Custom launch template for advanced config
    launchTemplate:
      id: lt-0123456789abcdef0
      version: "1"

  # Application workload node group  
  - name: app-nodes
    instanceTypes: ["m5.large", "m5.xlarge", "m4.large"]  # Multiple types
    minSize: 3
    maxSize: 20
    desiredCapacity: 6
    
    # Mix of spot and on-demand for cost optimization
    spot: true
    spotInstancePools: 3  # Diversify across instance types
    
    labels:
      node-role: application
      workload-type: general
    
    # EBS optimization for database workloads
    volumeSize: 100
    volumeType: gp3
    volumeIOPS: 3000
    volumeThroughput: 150
    
    # IAM permissions for workloads
    iam:
      withAddonPolicies:
        autoScaler: true
        cloudWatch: true
        ebs: true
        efs: true
        loadBalancer: true

  # GPU workload node group
  - name: gpu-nodes  
    instanceTypes: ["p3.2xlarge", "p3.8xlarge"]
    minSize: 0  # Scale to zero when not needed
    maxSize: 5
    desiredCapacity: 0
    
    # GPU-optimized AMI
    amiFamily: AmazonLinux2GPU
    
    labels:
      node-role: gpu
      workload-type: ml
    
    taints:
      - key: nvidia.com/gpu
        value: "true"
        effect: NoSchedule

---
# FARGATE PROFILES - Serverless Workloads
fargateProfiles:
  # CI/CD workloads
  - name: ci-cd-fargate
    selectors:
      - namespace: ci-cd
        labels:
          compute-type: fargate
      - namespace: jenkins
    
    # Only private subnets for security
    subnets:
      - subnet-private-1a
      - subnet-private-1b
      - subnet-private-1c
    
    # Pod execution role for AWS service access
    podExecutionRoleARN: arn:aws:iam::123456789012:role/eks-fargate-pod-execution-role
    
    tags:
      Environment: production
      Team: platform
      CostCenter: engineering

  # Batch processing workloads  
  - name: batch-fargate
    selectors:
      - namespace: batch
        labels:
          job-type: data-processing
    
    # Resource tags for cost allocation
    tags:
      Environment: production
      Workload: batch-processing
      Team: data-science

---
# SELF-MANAGED NODE GROUP (Advanced)
# Note: Requires custom AMI and bootstrap script
nodeGroups:
  - name: custom-nodes
    instanceType: m5.large
    
    # Custom AMI with pre-installed tools
    ami: ami-0123456789abcdef0
    
    # Custom user data script
    preBootstrapCommands:
      - "echo 'Installing custom security agent'"
      - "/opt/install-security-agent.sh"
    
    # Custom networking
    subnet: subnet-0123456789abcdef0
    securityGroups:
      attachIDs: 
        - sg-custom-security-group
    
    # SSH access (not recommended for production)
    ssh:
      allow: true
      publicKeyName: my-key-pair
      sourceSecurityGroupIds: 
        - sg-bastion-hosts
```

</details>

---

## 🌐 VPC CNI Deep Dive - Why It's Different

### **Traditional Kubernetes Networking vs VPC CNI**

| Traditional K8s | **VPC CNI** | **Why VPC CNI is Better** |
|----------------|-------------|---------------------------|
| Overlay network (flannel, calico) | Native VPC routing | **Better performance** - no encapsulation overhead |
| Pod IPs from cluster CIDR | Pod IPs from VPC subnets | **AWS service integration** - Security Groups for pods |
| NAT for external access | Direct internet access | **Simplified networking** - no complex NAT rules |

### **VPC CNI Architecture Philosophy**

**Core principle:** Pods are first-class VPC citizens
- **No overlay network** - pods get real VPC IP addresses
- **Direct routing** - packets flow through VPC routing tables
- **Security group compatibility** - pods can have security groups
- **Cloud-native integration** - works with VPC Flow Logs, Network ACLs

### **ENI (Elastic Network Interface) Allocation**

**Why ENIs matter:**
- Each node has **limited ENI capacity** based on instance type
- Each ENI has **limited secondary IP addresses**
- **Pod density** = (ENIs per node) × (IPs per ENI) - 1 (for primary IP)

**Optimization strategies:**
- **Prefix delegation** - allocate /28 blocks instead of individual IPs
- **Custom networking** - separate subnets for pods vs nodes
- **IP warming** - pre-allocate IPs for faster pod starts

### **Security Groups for Pods**

**Revolutionary feature:** Apply AWS Security Groups directly to pods
- **Granular network security** at pod level
- **AWS-native tool integration** - CloudFormation, Terraform
- **Compliance benefits** - network controls in familiar AWS constructs

<details>
<summary>📘 Click to see VPC CNI Configuration Examples</summary>

```yaml
# VPC CNI Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: amazon-vpc-cni
  namespace: kube-system
data:
  # Enable prefix delegation for more IPs per node
  enable-prefix-delegation: "true"
  
  # Warm prefix pools for faster pod startup
  warm-prefix-target: "1"
  warm-ip-target: "3"
  minimum-ip-target: "2"
  
  # Enable security groups for pods
  enable-pod-eni: "true"
  
  # Custom pod subnet (separate from node subnet)
  enable-custom-networking: "true"
  
  # Network plugin log level
  log-level: "DEBUG"  # Change to INFO for production

---
# Security Groups for Pods
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: database-pods-sg-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgresql
      tier: database
  securityGroups:
    groupIds:
      - sg-0123456789abcdef0  # Database security group

---
# ENI Config for custom networking
apiVersion: crd.k8s.amazonaws.com/v1alpha1
kind: ENIConfig
metadata:
  name: pod-subnet-config
spec:
  subnet: subnet-pod-1a  # Dedicated pod subnet
  securityGroups:
    - sg-pod-security-group

---
# Node labeling for ENI config
apiVersion: v1
kind: Node
metadata:
  name: ip-10-0-1-100.ec2.internal
  annotations:
    k8s.amazonaws.com/eniConfig: pod-subnet-config  # Use custom ENI config
```

</details>

---

## 🔐 IAM Integration - IRSA Deep Dive

### **Why IRSA Exists - The Problem It Solves**

**Before IRSA:**
- **Long-lived credentials** stored in secrets
- **Broad permissions** - one role for entire cluster
- **Manual rotation** of access keys
- **No audit trail** of which pod accessed what

**After IRSA:**
- **Short-lived tokens** (1 hour default, auto-renewed)
- **Granular permissions** - one role per service account
- **Automatic rotation** by Kubernetes
- **Full audit trail** in CloudTrail

### **IRSA Technical Architecture**

1. **OIDC Identity Provider** - EKS cluster has OIDC endpoint
2. **Service Account Token** - Kubernetes generates JWT token
3. **IAM Trust Relationship** - IAM role trusts OIDC provider
4. **STS AssumeRole** - AWS SDK exchanges token for credentials
5. **Temporary Credentials** - Used to access AWS services

**Why this architecture?**
- **No secrets in pods** - tokens are mounted automatically
- **Kubernetes-native** - uses standard service account mechanism  
- **AWS-native** - uses standard IAM roles and STS
- **Short-lived** - reduces blast radius of compromised credentials

### **IRSA Best Practices**

#### **Principle of Least Privilege**
- **One role per service account** - don't share roles
- **Specific resource ARNs** - avoid wildcard permissions
- **Condition keys** - use aws:userid, aws:RequestedRegion

#### **Security Hardening**
- **External ID** for extra security layer
- **Session policies** for additional restrictions
- **Resource-based policies** for cross-account access

<details>
<summary>📘 Click to see IRSA Implementation Examples</summary>

```yaml
# IRSA Setup with Terraform
data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  
  tags = {
    Name = "${var.cluster_name}-oidc"
  }
}

# IAM Role for S3 Access
resource "aws_iam_role" "s3_access" {
  name = "${var.cluster_name}-s3-access-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks.arn
        }
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub": "system:serviceaccount:production:s3-access-sa"
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud": "sts.amazonaws.com"
          }
          StringLike = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud": "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Granular S3 Policy
resource "aws_iam_role_policy" "s3_policy" {
  name = "s3-bucket-policy"
  role = aws_iam_role.s3_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::my-app-bucket/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption": "AES256"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::my-app-bucket"
        ]
        Condition = {
          StringLike = {
            "s3:prefix": [
              "app-data/${aws:userid}/*"
            ]
          }
        }
      }
    ]
  })
}

---
# Service Account with IRSA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-access-sa
  namespace: production
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/eks-s3-access-role
automountServiceAccountToken: true

---
# Deployment using IRSA
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-app
  namespace: production
spec:
  template:
    spec:
      serviceAccountName: s3-access-sa
      containers:
      - name: app
        image: myapp:latest
        env:
        # AWS SDK automatically picks up these environment variables
        - name: AWS_ROLE_ARN
          value: "arn:aws:iam::123456789012:role/eks-s3-access-role"
        - name: AWS_WEB_IDENTITY_TOKEN_FILE
          value: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
        - name: AWS_DEFAULT_REGION
          value: "us-west-2"
        
        # Token is automatically mounted here
        volumeMounts:
        - name: aws-iam-token
          mountPath: /var/run/secrets/eks.amazonaws.com/serviceaccount
          readOnly: true
      
      # Projected volume for the token
      volumes:
      - name: aws-iam-token
        projected:
          sources:
          - serviceAccountToken:
              audience: sts.amazonaws.com
              expirationSeconds: 3600
              path: token

---
# Cross-account access example
# IAM Role in Account B trusting Account A's EKS
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT-A:role/eks-cross-account-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id"
        }
      }
    }
  ]
}
```

</details>

---

## 💾 Storage Integration - EBS, EFS, and FSx

### **Why Multiple Storage Types?**

Different workloads have different storage characteristics:

| Storage Type | **Performance** | **Consistency** | **Sharing** | **Use Case** |
|-------------|---------------|-----------------|-------------|--------------|
| **EBS** | High IOPS/throughput | Strong | Single pod | Databases, file systems |
| **EFS** | Variable | Eventual | Multiple pods | Shared data, content |
| **FSx Lustre** | Ultra-high | Strong | Multiple pods | HPC, ML training |
| **FSx NetApp** | Enterprise | Strong | Multiple pods | Enterprise apps |

### **EBS CSI Driver - Block Storage**

**Philosophy:** High-performance, consistent storage for single pods
- **gp3 by default** - better price/performance than gp2
- **Encryption at rest** - KMS integration
- **Snapshot support** - Point-in-time recovery
- **Volume expansion** - Grow volumes without pod restart

### **EFS CSI Driver - Shared Storage**

**Philosophy:** POSIX-compliant shared file system
- **Multiple access modes** - ReadWriteMany support
- **Automatic scaling** - pay for what you use
- **Performance modes** - General Purpose vs Max IO
- **Throughput modes** - Provisioned vs Burstable

<details>
<summary>📘 Click to see Storage Configuration Examples</summary>

```yaml
# EBS StorageClass with encryption
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: gp3-encrypted
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  iops: "3000"
  throughput: "125"
  encrypted: "true"
  kmsKeyId: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer  # Ensures pod and volume in same AZ

---
# EFS StorageClass for shared storage
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: efs-shared
provisioner: efs.csi.aws.com
parameters:
  provisioningMode: efs-ap  # Creates access points
  fileSystemId: fs-0123456789abcdef0
  directoryPerms: "0755"
  gidRangeStart: "1000"
  gidRangeEnd: "2000"
  basePath: "/shared-data"
  
  # EFS performance settings
  performanceMode: generalPurpose  # or maxIO
  throughputMode: provisioned
  provisionedThroughputInMibps: "100"

---
# StatefulSet with EBS storage
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: database
spec:
  serviceName: database
  replicas: 3
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: gp3-encrypted
      resources:
        requests:
          storage: 100Gi
  template:
    spec:
      containers:
      - name: postgres
        image: postgres:13
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
        env:
        - name: POSTGRES_DB
          value: myapp
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password

---
# Shared storage with EFS
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: shared-storage
spec:
  accessModes:
    - ReadWriteMany  # Multiple pods can mount
  storageClassName: efs-shared
  resources:
    requests:
      storage: 100Gi  # Ignored by EFS, pay for actual usage

---
# Multiple pods sharing EFS
apiVersion: apps/v1
kind: Deployment
metadata:
  name: content-app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: nginx
        volumeMounts:
        - name: shared-content
          mountPath: /usr/share/nginx/html
      volumes:
      - name: shared-content
        persistentVolumeClaim:
          claimName: shared-storage

---
# FSx Lustre for HPC workloads
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fsx-lustre
provisioner: fsx.csi.aws.com
parameters:
  subnetId: subnet-0123456789abcdef0
  securityGroupIds: sg-0123456789abcdef0
  deploymentType: PERSISTENT_2  # or SCRATCH_1, SCRATCH_2
  perUnitStorageThroughput: "250"  # MB/s per TiB
  dataRepositoryPath: s3://my-hpc-bucket/  # Link to S3 bucket
```

</details>

---

## 📊 Monitoring and Observability - CloudWatch Integration

### **Why CloudWatch Container Insights?**

**Native AWS integration** for Kubernetes monitoring:
- **No additional infrastructure** - managed by AWS
- **Cost-effective** - pay-as-you-go pricing
- **Integration with other AWS services** - alarms, dashboards, logs

### **Container Insights Architecture**

**Components:**
- **CloudWatch Agent** - collects metrics and logs
- **FluentBit** - log forwarding and parsing  
- **X-Ray** - distributed tracing
- **Application Insights** - automatic application monitoring

**Metrics collected:**
- **Node metrics** - CPU, memory, disk, network
- **Pod metrics** - resource usage, restart counts
- **Namespace metrics** - aggregated resource usage
- **Service metrics** - request rates, error rates

<details>
<summary>📘 Click to see Monitoring Configuration Examples</summary>

```yaml
# CloudWatch Agent Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: cwagentconfig
  namespace: amazon-cloudwatch
data:
  cwagentconfig.json: |
    {
      "agent": {
        "region": "us-west-2"
      },
      "logs": {
        "metrics_collected": {
          "kubernetes": {
            "cluster_name": "my-eks-cluster",
            "metrics_collection_interval": 60
          }
        },
        "force_flush_interval": 15
      },
      "metrics": {
        "namespace": "CWAgent",
        "metrics_collected": {
          "cpu": {
            "measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"],
            "metrics_collection_interval": 60,
            "resources": ["*"],
            "totalcpu": false
          },
          "disk": {
            "measurement": ["used_percent"],
            "metrics_collection_interval": 60,
            "resources": ["*"]
          },
          "diskio": {
            "measurement": ["io_time", "read_bytes", "write_bytes", "reads", "writes"],
            "metrics_collection_interval": 60,
            "resources": ["*"]
          },
          "mem": {
            "measurement": ["mem_used_percent"],
            "metrics_collection_interval": 60
          },
          "netstat": {
            "measurement": ["tcp_established", "tcp_time_wait"],
            "metrics_collection_interval": 60
          }
        }
      }
    }

---
# Application monitoring with X-Ray
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: xray-daemon
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: xray-daemon
        image: amazon/aws-xray-daemon:latest
        command: ["/usr/bin/xray", "-b", "0.0.0.0:2000"]
        resources:
          limits:
            memory: "256Mi"
            cpu: "256m"
          requests:
            memory: "32Mi"
            cpu: "32m"
        ports:
        - containerPort: 2000
          protocol: UDP
        - containerPort: 2000
          protocol: TCP

---
# Prometheus integration with AMP (Amazon Managed Prometheus)
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: prometheus
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    
    remote_write:
      - url: https://aps-workspaces.us-west-2.amazonaws.com/workspaces/ws-12345678-1234-1234-1234-123456789012/api/v1/remote_write
        queue_config:
          max_samples_per_send: 1000
          max_shards: 200
          capacity: 2500
        
        # IRSA for AMP access
        sigv4:
          region: us-west-2
    
    scrape_configs:
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true

---
# Grafana dashboard for EKS
apiVersion: v1
kind: ConfigMap
metadata:
  name: eks-dashboard
data:
  dashboard.json: |
    {
      "dashboard": {
        "title": "EKS Cluster Overview",
        "panels": [
          {
            "title": "Node CPU Usage",
            "type": "graph",
            "targets": [
              {
                "expr": "100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"
              }
            ]
          },
          {
            "title": "Pod Memory Usage",
            "type": "graph", 
            "targets": [
              {
                "expr": "container_memory_usage_bytes{container!=\"POD\",container!=\"\"}"
              }
            ]
          }
        ]
      }
    }
```

</details>

---

## 🛡️ Security Best Practices - Defense in Depth

### **EKS Security Model**

**Layered security approach:**
1. **Infrastructure** - VPC, security groups, NACLs
2. **Cluster** - RBAC, network policies, pod security
3. **Workload** - container security, secrets management
4. **Data** - encryption at rest and in transit

### **Network Security**

#### **Private Clusters**
- **Control plane in AWS VPC** - no internet access
- **Worker nodes in private subnets** - NAT gateway for outbound
- **VPC endpoints** - private connectivity to AWS services

#### **Security Groups**
- **Pod-level security groups** - granular network controls
- **Least privilege** - specific port and protocol rules
- **Segmentation** - separate groups for different tiers

<details>
<summary>📘 Click to see Security Configuration Examples</summary>

```yaml
# Private EKS cluster configuration
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: private-cluster
  region: us-west-2

# Private cluster setup
privateCluster:
  enabled: true
  skipEndpointCreation: false

clusterEndpoint:
  privateAccess: true
  publicAccess: false

# VPC configuration for private cluster
vpc:
  subnets:
    private:
      us-west-2a: { cidr: "10.0.1.0/24" }
      us-west-2b: { cidr: "10.0.2.0/24" }
      us-west-2c: { cidr: "10.0.3.0/24" }
    # No public subnets defined - fully private
  
  nat:
    gateway: HighlyAvailable  # NAT gateway for outbound access

---
# Pod Security Standards
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# Security Context best practices
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      # Pod-level security
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: app
        image: myapp:latest
        
        # Container-level security
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
            # Only add specific capabilities if needed
            # add: ["NET_BIND_SERVICE"]
        
        # Resource limits for stability
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        
        # Use ephemeral volumes for writable directories
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: cache-volume
          mountPath: /app/cache
      
      volumes:
      - name: tmp-volume
        emptyDir: {}
      - name: cache-volume
        emptyDir: {}

---
# Network policy for microsegmentation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
      tier: frontend
  
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow traffic from load balancer
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-system
    ports:
    - protocol: TCP
      port: 8080
  
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
  
  # Allow access to database
  - to:
    - podSelector:
        matchLabels:
          app: database
          tier: data
    ports:
    - protocol: TCP
      port: 5432

---
# Secrets management with AWS Secrets Manager
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
# External Secret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: production
spec:
  refreshInterval: 15m
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: production/database
      property: password
  - secretKey: api-key
    remoteRef:
      key: production/api-keys
      property: third-party-service
```

</details>

---

## ⚡ Interview Success Tips

### **How to Approach EKS Questions**

1. **Start with AWS benefits** - Why EKS vs self-managed K8s?
2. **Explain the shared responsibility** - What AWS manages vs what you manage
3. **Mention cost implications** - Control plane cost, data transfer, storage
4. **Security considerations** - IRSA, private clusters, VPC integration
5. **Operational benefits** - Managed updates, HA, AWS service integration

### **Common EKS Interview Topics**

| Topic | **What to Emphasize** | **Avoid** |
|-------|---------------------|-----------|
| **IRSA** | Security benefits, no secrets in pods | Just explaining the mechanics |
| **VPC CNI** | Performance benefits, security groups for pods | Getting lost in networking details |
| **Fargate** | When to use vs managed nodes, cost implications | Saying it's always better |
| **Node Groups** | Mix of on-demand/spot, different instance types | One-size-fits-all approach |
| **Monitoring** | Native AWS integration, cost considerations | Only mentioning Prometheus |

---

> 💡 **EKS Interview Success Tip**: Always connect EKS features back to business value - reduced operational overhead, better security posture, cost optimization, and faster time to market. Show you understand not just the "how" but the "why" behind AWS's design decisions.

---

**🎯 Key Takeaway:**
EKS combines the power of Kubernetes with AWS's operational excellence and native service integrations. Understanding when and why to use EKS-specific features versus standard Kubernetes approaches demonstrates senior-level cloud architecture thinking.