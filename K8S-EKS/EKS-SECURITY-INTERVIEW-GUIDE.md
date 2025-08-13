# 🛡️ EKS Security - AWS-Specific Interview Deep Dive

> **☁️ Master EKS Security for Senior Cloud DevOps Roles** - AWS-specific security controls and best practices

---

## 🏗️ EKS Security Architecture - Why AWS Built It This Way

### **The Security Problem EKS Solves**

Before EKS, securing Kubernetes on AWS required:
- **Manual security hardening** - Securing API server, etcd, networking
- **Complex certificate management** - PKI infrastructure for cluster communication
- **Inconsistent security policies** - Different teams implementing different approaches
- **Security update coordination** - Manual patching of control plane components
- **Compliance challenges** - Meeting enterprise security requirements

**EKS Security Philosophy:**
- **Secure by default** - AWS handles security hardening of managed components
- **Defense in depth** - Multiple layers of security controls
- **AWS-native integration** - Leverage existing AWS security services
- **Shared responsibility** - Clear boundaries between AWS and customer responsibilities

### 🎛️ Control Plane Security - Why AWS Manages It

| Component | **Why AWS Manages It** | **Security Benefits** | **Your Focus Areas** |
|-----------|----------------------|---------------------|---------------------|
| **🧠 API Server** | Complex TLS/PKI management | Always-on encryption, cert rotation | Authentication design, RBAC policies |
| **⚡ etcd** | Critical data store security | Automated backups, encryption at rest | Secrets strategy, data classification |
| **📋 Control Plane** | High availability requirements | Multi-AZ redundancy, auto-patching | Network access controls, monitoring |
| **🌐 Endpoints** | Network exposure management | Private/public options, CIDR controls | VPN/bastion architecture, access patterns |

### 🔒 Shared Responsibility - Security Boundaries

**AWS Responsibilities (Infrastructure Security):**
- **Physical security** - Data center access, hardware security
- **Host operating system** - Patches, hardening, compliance
- **Network infrastructure** - DDoS protection, network ACLs
- **Service orchestration** - API server, scheduler, controller manager

**Customer Responsibilities (Configuration Security):**
- **Identity & Access Management** - Who can access what resources
- **Network configuration** - VPC setup, security groups, network policies
- **Application security** - Container images, runtime security
- **Data protection** - Encryption, secrets management, compliance

**Why this model works:**
- **Expertise alignment** - AWS focuses on infrastructure, customers on applications
- **Scale benefits** - AWS security investments benefit all customers
- **Compliance framework** - Clear accountability for audits
- **Operational efficiency** - Customers focus on business logic, not infrastructure

---

## 🔐 IAM Integration - Why IRSA Changes Everything

### **The Credential Management Problem**

Traditional Kubernetes + AWS integration challenges:
- **Long-lived access keys** - Rotation complexity, broad permissions
- **Credential storage** - Keys in ConfigMaps/Secrets, security risks
- **Access granularity** - One set of credentials per cluster/namespace
- **Audit limitations** - Difficult to trace which pod accessed what

### 🎭 IRSA Architecture - Token Exchange Security Model

**Why IRSA is revolutionary:**
1. **No secrets in pods** - Uses Kubernetes service account tokens
2. **Automatic credential rotation** - Tokens expire and refresh automatically
3. **Fine-grained permissions** - One IAM role per service account
4. **Full audit trail** - CloudTrail shows which pod made which AWS API call
5. **Zero-trust approach** - Temporary credentials, principle of least privilege

**Technical Flow - Why Each Step Matters:**
1. **Kubernetes generates JWT token** - Cryptographically signed by cluster
2. **AWS STS validates token** - Verifies signature against OIDC provider
3. **IAM role assumption** - Temporary credentials issued (15min-12hr)
4. **AWS SDK automatically refreshes** - No application code changes needed

### **IRSA Security Benefits Over Traditional Methods**

| Traditional Method | **Security Issues** | **IRSA Solution** | **Why It's Better** |
|-------------------|-------------------|-------------------|--------------------|
| EC2 Instance Profiles | All pods inherit same permissions | Per-service account roles | Principle of least privilege |
| Access Keys in Secrets | Long-lived, rotation complexity | Temporary tokens | Automatic rotation, shorter lifetime |
| Shared credentials | No audit granularity | Individual identity | Full traceability per workload |
| Manual key management | Human error, credential sprawl | Automatic token handling | Reduces operational overhead |

### 🎭 IAM Roles for Service Accounts (IRSA) - Implementation

<details>
<summary>📘 Click to see IRSA Service Account Configuration</summary>

```yaml
# 🆔 Service Account with IRSA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-read-only-sa
  namespace: production
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/EKS-S3-ReadOnly-Role

---
# 🚀 Deployment using IRSA
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-s3-access
spec:
  template:
    spec:
      serviceAccountName: s3-read-only-sa
      containers:
      - name: app
        image: myapp:latest
        env:
        # 🔑 AWS SDK automatically discovers these
        - name: AWS_ROLE_ARN
          value: "arn:aws:iam::123456789012:role/EKS-S3-ReadOnly-Role"
        - name: AWS_WEB_IDENTITY_TOKEN_FILE
          value: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
        volumeMounts:
        - name: aws-iam-token
          mountPath: /var/run/secrets/eks.amazonaws.com/serviceaccount
          readOnly: true
      volumes:
      - name: aws-iam-token
        projected:
          sources:
          - serviceAccountToken:
              audience: sts.amazonaws.com
              expirationSeconds: 3600
              path: token
```

</details>

### 🏗️ IRSA Infrastructure Setup - Trust Relationship Security

<details>
<summary>📘 Click to see IRSA Terraform Configuration</summary>

```hcl
# 🎯 OIDC Identity Provider - Establishes trust between EKS and IAM
data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  
  tags = {
    Name = "${var.cluster_name}-oidc"
    Purpose = "EKS-IRSA-Authentication"
  }
}

# 🔐 IAM Role with strict conditions
resource "aws_iam_role" "s3_read_only" {
  name = "EKS-S3-ReadOnly-Role"
  
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
            # Specific service account binding
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub": "system:serviceaccount:production:s3-read-only-sa"
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud": "sts.amazonaws.com"
          }
          StringLike = {
            # Additional namespace/name constraints
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub": "system:serviceaccount:production:*"
          }
        }
      }
    ]
  })
}

# Custom policy instead of AWS managed - principle of least privilege
resource "aws_iam_role_policy" "s3_specific_access" {
  name = "s3-limited-access"
  role = aws_iam_role.s3_read_only.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::specific-app-bucket",
          "arn:aws:s3:::specific-app-bucket/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption": "AES256"
          }
        }
      }
    ]
  })
}
```

</details>

### 🔒 Least Privilege IAM Policies - Security Through Constraints

**Why condition-based policies matter:**
- **Prevent privilege escalation** - Even compromised workloads are limited
- **Data isolation** - Workloads can only access their designated resources
- **Compliance requirements** - Meet regulatory standards for data access
- **Audit trails** - Clear mapping of which workload accessed what

<details>
<summary>📘 Click to see Advanced IAM Policy Examples</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3AccessWithEncryptionEnforcement",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-bucket",
        "arn:aws:s3:::my-app-bucket/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        },
        "StringLike": {
          "s3:prefix": [
            "app-data/${aws:userid}/*",
            "shared-data/*"
          ]
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "2024-01-01T00:00:00Z"
        },
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8"]  # VPC CIDR only
        }
      }
    },
    {
      "Sid": "ParameterStoreWithDecryption",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": "arn:aws:ssm:us-west-2:123456789012:parameter/myapp/*",
      "Condition": {
        "StringEquals": {
          "ssm:Decrypt": "true",
          "aws:RequestedRegion": "us-west-2"
        },
        "ForAllValues:StringLike": {
          "ssm:ParameterName": [
            "/myapp/prod/*",
            "/shared/config/*"
          ]
        }
      }
    },
    {
      "Sid": "SecretsManagerReadOnly",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-west-2:123456789012:secret:myapp/*",
      "Condition": {
        "StringEquals": {
          "secretsmanager:VersionStage": "AWSCURRENT"
        },
        "NumericLessThan": {
          "aws:TokenIssueTime": "${aws:CurrentTime - 3600}"
        }
      }
    }
  ]
}
```

</details>

---

## 🌐 VPC and Network Security - AWS-Native Network Controls

### **Why EKS Network Security is Different**

**Traditional Kubernetes networking challenges:**
- **Overlay complexity** - CNI plugins with different security models
- **Limited integration** - Network policies don't integrate with cloud security groups
- **Visibility gaps** - Difficult to correlate pod traffic with cloud monitoring
- **Compliance complexity** - Network controls scattered across multiple systems

**EKS VPC-native approach benefits:**
- **Direct VPC integration** - Pods get real VPC IP addresses
- **Security group compatibility** - Apply AWS security groups to pods
- **Native monitoring** - VPC Flow Logs capture all pod traffic
- **Familiar tools** - Use existing AWS network security knowledge

### 🔒 Security Groups - Multi-Layer Defense Strategy

**Security group hierarchy philosophy:**
1. **Cluster level** - Base connectivity for EKS components
2. **Node level** - Worker node communication and management
3. **Pod level** - Application-specific network policies
4. **Service level** - Load balancer and ingress controls

**Why multiple security groups matter:**
- **Defense in depth** - Multiple layers of network filtering
- **Granular control** - Different rules for different components
- **Easy troubleshooting** - Clear separation of concerns
- **Compliance** - Meet regulatory requirements for network segmentation

<details>
<summary>📘 Click to see Security Group Configuration</summary>

```hcl
# 🛡️ EKS Cluster Security Group - Control plane protection
resource "aws_security_group" "eks_cluster" {
  name_prefix = "eks-cluster-sg"
  vpc_id      = var.vpc_id
  description = "Security group for EKS cluster control plane"

  # 🌐 HTTPS API access - restricted to internal networks
  ingress {
    description = "HTTPS API access from internal networks"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # RFC 1918 private networks only
  }

  # 📡 Outbound for AWS service communication
  egress {
    description = "All outbound for AWS services"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-cluster-security-group"
    Purpose = "EKS-Control-Plane"
    Environment = var.environment
  }
}

# 🔧 Worker Node Security Group - Node-to-node and kubelet communication
resource "aws_security_group" "eks_nodes" {
  name_prefix = "eks-node-group-sg"
  vpc_id      = var.vpc_id
  description = "Security group for EKS worker nodes"

  # 🔗 Node-to-node communication for pod networking
  ingress {
    description = "Node-to-node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # 🔗 Node-to-node UDP for DNS and other services
  ingress {
    description = "Node-to-node UDP communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    self        = true
  }

  # 🎛️ Control plane to kubelet communication
  ingress {
    description     = "Control plane to kubelet"
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # 🔍 Webhook and API server communication
  ingress {
    description     = "Webhook communication from control plane"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # 🌐 All outbound - required for pulling images, AWS API calls
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-node-group-security-group"
    Purpose = "EKS-Worker-Nodes"
    Environment = var.environment
  }
}

# 🔒 Additional security group for pod-level controls
resource "aws_security_group" "pod_security_groups" {
  for_each = var.pod_security_groups
  
  name_prefix = "eks-pod-${each.key}-sg"
  vpc_id      = var.vpc_id
  description = "Pod-level security group for ${each.key} workloads"

  dynamic "ingress" {
    for_each = each.value.ingress_rules
    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
      security_groups = ingress.value.security_groups
    }
  }

  dynamic "egress" {
    for_each = each.value.egress_rules
    content {
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
      security_groups = egress.value.security_groups
    }
  }

  tags = {
    Name = "eks-pod-${each.key}-security-group"
    Purpose = "Pod-Level-Security"
    Workload = each.key
  }
}
```

</details>

### 🛡️ Security Groups for Pods - Granular Network Control

**Why pod-level security groups are game-changing:**
- **Microsegmentation** - Network policies at individual pod level
- **AWS-native tools** - Use familiar security group concepts
- **Compliance alignment** - Network controls map to business requirements
- **Integration benefits** - Works with AWS monitoring and logging

**Security group strategy patterns:**
1. **Tier-based** - Frontend, backend, database security groups
2. **Application-based** - One security group per application
3. **Environment-based** - Dev, staging, prod isolation
4. **Compliance-based** - PCI, HIPAA, SOX requirements

<details>
<summary>📘 Click to see Pod Security Group Policies</summary>

```yaml
# 🔐 Database tier security - most restrictive
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: database-pod-sg-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgresql
      tier: database
      security-zone: restricted
  securityGroups:
    groupIds:
      - sg-0123456789abcdef0  # Database access SG
      # Allows only:
      # - Ingress from backend tier on port 5432
      # - Egress for DNS resolution
      # - No internet access

---
# 🌐 Backend application security group
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: backend-api-sg-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend-api
      tier: backend
  securityGroups:
    groupIds:
      - sg-0987654321fedcba0  # Backend API SG
      # Allows:
      # - Ingress from frontend tier on port 8080
      # - Egress to database tier on port 5432
      # - Egress to AWS services (S3, SES, etc.)
      # - No direct internet access

---
# 🎨 Frontend application security group
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: frontend-web-sg-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
      tier: frontend
  securityGroups:
    groupIds:
      - sg-0abc123def456789  # Frontend web SG
      # Allows:
      # - Ingress from ALB security group on port 8080
      # - Egress to backend tier on port 8080
      # - Egress for CDN/external APIs (port 443)

---
# 🔧 Batch processing pods - temporary access
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: batch-processing-sg-policy
  namespace: batch-jobs
spec:
  podSelector:
    matchLabels:
      job-type: data-processing
      compute-type: batch
  securityGroups:
    groupIds:
      - sg-0batch987654321  # Batch processing SG
      # Allows:
      # - Egress to S3 endpoints
      # - Egress to RDS for data export
      # - Time-limited access patterns
      # - No ingress (initiated jobs only)

---
# 🚀 CI/CD pipeline security group
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: cicd-runner-sg-policy
  namespace: ci-cd
spec:
  podSelector:
    matchLabels:
      app: gitlab-runner
      environment: build
  securityGroups:
    groupIds:
      - sg-0cicd123456789  # CI/CD runner SG
      # Allows:
      # - Egress to Git repositories
      # - Egress to container registries
      # - Egress to deployment targets
      # - Time-bounded access for builds
```

</details>

### 🌐 Private EKS Cluster - Maximum Security Posture

**Why private clusters are essential for enterprise security:**
- **Zero internet exposure** - Control plane never accessible from internet
- **Reduced attack surface** - No public endpoints to target
- **Compliance requirements** - Meet regulatory standards for network isolation
- **Data sovereignty** - All communication stays within your network perimeter

**Private cluster architecture considerations:**
1. **VPN/Direct Connect required** - For management access
2. **Bastion hosts** - Secure jump boxes for emergency access
3. **VPC endpoints** - Private connectivity to AWS services
4. **NAT Gateway strategy** - Outbound internet for updates/images

<details>
<summary>📘 Click to see Private Cluster Configuration</summary>

```yaml
# 🔒 Private cluster with enhanced security
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: private-cluster
  region: us-west-2
  
  # Security tags for compliance
  tags:
    Environment: production
    Compliance: "SOC2,HIPAA"
    SecurityZone: restricted
    DataClassification: sensitive

# 🏠 Full private cluster configuration
privateCluster:
  enabled: true
  skipEndpointCreation: false
  additionalEndpointServices:  # VPC endpoints for AWS services
    - com.amazonaws.us-west-2.s3
    - com.amazonaws.us-west-2.ec2
    - com.amazonaws.us-west-2.ecr.dkr
    - com.amazonaws.us-west-2.ecr.api
    - com.amazonaws.us-west-2.sts
    - com.amazonaws.us-west-2.ssm
    - com.amazonaws.us-west-2.secretsmanager

# 🔐 Endpoint access - no public access
clusterEndpoint:
  privateAccess: true   # Enable private access
  publicAccess: false   # Disable public access completely
  publicAccessCidrs: []  # Empty list - no public CIDRs

# 🌐 VPC configuration with private subnets only
vpc:
  # Custom CIDR for network isolation
  cidr: "10.10.0.0/16"
  
  subnets:
    private:
      # Multi-AZ for high availability
      us-west-2a: { cidr: "10.10.1.0/24" }
      us-west-2b: { cidr: "10.10.2.0/24" }
      us-west-2c: { cidr: "10.10.3.0/24" }
  
  # No public subnets defined for maximum security
  # public: {}  # Commented out intentionally
  
  # DNS configuration
  hostnames:
    enableDnsHostnames: true
    enableDnsSupport: true

# 📡 Highly available NAT Gateway configuration
nat:
  gateway: HighlyAvailable  # NAT Gateway in each AZ
  
# 🔒 Secure node groups configuration
managedNodeGroups:
  - name: private-workers-system
    instanceType: t3.medium
    minSize: 2
    maxSize: 4
    desiredCapacity: 2
    
    # Force private networking
    privateNetworking: true
    
    # Use specific private subnets
    subnets:
      - private-subnet-1a
      - private-subnet-1b
      - private-subnet-1c
    
    # Security hardening
    ssh:
      allow: false  # No SSH access for security
    
    # Instance metadata service security
    instanceMetadataOptions:
      httpTokens: required        # Require IMDSv2
      httpPutResponseHopLimit: 2  # Limit metadata access
    
    # Labels for system workloads
    labels:
      node-type: system
      security-zone: private
      workload: system-services
    
    # Taints to separate system and application workloads
    taints:
      - key: CriticalAddonsOnly
        value: "true"
        effect: NoSchedule
    
    # Security-focused instance profile
    iam:
      instanceProfileARN: "arn:aws:iam::123456789012:instance-profile/EKS-NodeGroup-Private-InstanceProfile"

  - name: private-workers-app
    instanceTypes: ["m5.large", "m5.xlarge"]
    minSize: 3
    maxSize: 20
    desiredCapacity: 6
    
    privateNetworking: true
    
    # Mixed instance types for cost optimization
    mixedInstancesPolicy:
      instancesDistribution:
        maxPrice: 0.10
        spotInstancePools: 4
        spotAllocationStrategy: "diversified"
        onDemandBaseCapacity: 2
        onDemandPercentageAboveBaseCapacity: 25
    
    ssh:
      allow: false
    
    # Enhanced security for application workloads
    labels:
      node-type: application
      security-zone: private
      workload: application-services
    
    # EBS encryption for data at rest
    volumeSize: 100
    volumeType: gp3
    volumeEncrypted: true
    volumeKmsKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"

# 📊 Enhanced logging for security monitoring
cloudWatch:
  clusterLogging:
    enable: true
    types:
      - api        # API server logs
      - audit      # Audit logs for compliance
      - authenticator  # Authentication logs
      - controllerManager  # Controller manager logs
      - scheduler  # Scheduler logs
    
    # Log retention for compliance
    logRetentionInDays: 30

# 🔐 Encryption configuration
secretEncryption:
  # Use customer-managed KMS key
  keyARN: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
```

</details>

---

## 🔑 Encryption and Secrets - Defense in Depth Strategy

### **Why Multi-Layer Encryption Matters**

**Threat model considerations:**
- **Data at rest** - Disk encryption, database encryption, backup encryption
- **Data in transit** - TLS everywhere, mTLS for service-to-service
- **Data in memory** - Runtime encryption, secure enclaves
- **Key management** - Rotation, access control, audit trails

**EKS encryption layers:**
1. **Control plane encryption** - etcd encryption with KMS
2. **Worker node encryption** - EBS volume encryption
3. **Application data encryption** - Database and file system encryption
4. **Network encryption** - TLS termination and pod-to-pod encryption

### 🔒 EKS Encryption at Rest - Protecting Critical Data

**Why customer-managed KMS keys are essential:**
- **Key control** - You control key lifecycle and access
- **Compliance** - Meet regulatory requirements for key management
- **Audit capability** - Full CloudTrail logging of key usage
- **Cross-account access** - Share keys across AWS accounts securely

<details>
<summary>📘 Click to see KMS Encryption Configuration</summary>

```hcl
# 🔐 Customer-managed KMS key with comprehensive policy
resource "aws_kms_key" "eks_secrets" {
  description             = "EKS cluster secrets encryption key"
  deletion_window_in_days = 30  # Longer window for production safety
  enable_key_rotation    = true  # Automatic annual rotation
  
  # Comprehensive key policy for enterprise use
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEKSService"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService": "eks.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "AllowClusterServiceAccounts"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/EKS-*"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:SecretARN": "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:*"
          }
        }
      },
      {
        Sid    = "AllowLogDelivery"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "eks-secrets-encryption-key"
    Purpose = "EKS-Secrets-Encryption"
    Environment = var.environment
    DataClassification = "sensitive"
  }
}

# 🔑 KMS key alias for easier management
resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/eks-${var.cluster_name}-secrets"
  target_key_id = aws_kms_key.eks_secrets.key_id
}

# 🏗️ EKS cluster with comprehensive encryption
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version

  # 🔒 Encryption configuration for secrets
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]  # Encrypt all Kubernetes secrets
  }

  # 🌐 VPC configuration with security
  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = var.enable_public_access
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  # 📊 Comprehensive logging for security monitoring
  enabled_cluster_log_types = [
    "api",              # API server logs
    "audit",           # Kubernetes audit logs
    "authenticator",   # AWS IAM authenticator logs
    "controllerManager", # Controller manager logs
    "scheduler"        # Scheduler logs
  ]

  # Security hardening
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSVPCResourceController,
    aws_cloudwatch_log_group.eks
  ]

  tags = {
    Name = var.cluster_name
    Environment = var.environment
    ManagedBy = "Terraform"
    SecurityCompliance = "enabled"
  }
}

# 📊 CloudWatch log group with encryption
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_secrets.arn

  tags = {
    Name = "${var.cluster_name}-cluster-logs"
    Environment = var.environment
  }
}
```

</details>

### 🔐 External Secrets Management - Zero-Trust Secrets Strategy

**Why external secrets management is critical:**
- **Secret rotation** - Automatic rotation without pod restarts
- **Centralized management** - Single source of truth for secrets
- **Access control** - Fine-grained permissions per secret
- **Audit capability** - Track who accessed what secret when
- **Compliance** - Meet requirements for secrets handling

**External secrets architecture benefits:**
1. **No secrets in Git** - Never store credentials in repositories
2. **Runtime fetching** - Secrets pulled at runtime, not build time
3. **Least privilege** - Each workload gets only needed secrets
4. **Automatic updates** - Secret changes propagate automatically

<details>
<summary>📘 Click to see External Secrets Configuration</summary>

```yaml
# 🔧 External Secrets Operator configuration
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager-store
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
      # Role assumption for cross-account access
      role: "arn:aws:iam::123456789012:role/ExternalSecretsRole"

---
# 🔐 ExternalSecret with automatic rotation
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  refreshInterval: 30m  # Check for updates every 30 minutes
  secretStoreRef:
    name: aws-secrets-manager-store
    kind: SecretStore
  
  target:
    name: db-credentials
    creationPolicy: Owner
    deletionPolicy: Retain
    template:
      type: Opaque
      metadata:
        labels:
          app.kubernetes.io/managed-by: external-secrets
          secret-type: database
        annotations:
          secret-rotation: "enabled"
      data:
        # Template with transformation
        username: "{{ .username }}"
        password: "{{ .password }}"
        # Computed fields
        connection-string: "postgresql://{{ .username }}:{{ .password }}@{{ .host }}:{{ .port }}/{{ .database }}?sslmode=require"
  
  data:
  - secretKey: username
    remoteRef:
      key: prod/database/postgresql
      property: username
  - secretKey: password
    remoteRef:
      key: prod/database/postgresql
      property: password
  - secretKey: host
    remoteRef:
      key: prod/database/postgresql
      property: host
  - secretKey: port
    remoteRef:
      key: prod/database/postgresql
      property: port
  - secretKey: database
    remoteRef:
      key: prod/database/postgresql
      property: database

---
# 🗝️ API keys and certificates
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: api-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager-store
    kind: SecretStore
  
  target:
    name: api-secrets
    creationPolicy: Owner
    template:
      type: kubernetes.io/tls  # TLS certificate type
      data:
        tls.crt: "{{ .certificate | b64enc }}"
        tls.key: "{{ .private_key | b64enc }}"
        api-key: "{{ .api_key }}"
        webhook-secret: "{{ .webhook_secret }}"
  
  data:
  - secretKey: certificate
    remoteRef:
      key: prod/tls/app-certificate
      property: certificate
  - secretKey: private_key
    remoteRef:
      key: prod/tls/app-certificate
      property: private_key
  - secretKey: api_key
    remoteRef:
      key: prod/api/external-service
      property: api_key
  - secretKey: webhook_secret
    remoteRef:
      key: prod/api/external-service
      property: webhook_secret

---
# 🚀 Application deployment using external secrets
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
      annotations:
        # Restart pods when secrets change
        secrets.external-secrets.io/reload: "true"
    spec:
      serviceAccountName: app-service-account
      
      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      
      containers:
      - name: app
        image: myapp:v1.2.3
        
        # Use secrets as environment variables
        envFrom:
        - secretRef:
            name: db-credentials
        - secretRef:
            name: api-secrets
        
        # Use secrets as volume mounts for files
        volumeMounts:
        - name: tls-certificates
          mountPath: "/etc/ssl/certs"
          readOnly: true
        - name: config-files
          mountPath: "/etc/app/config"
          readOnly: true
        
        # Security hardening
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        
        # Resource limits
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      
      volumes:
      - name: tls-certificates
        secret:
          secretName: api-secrets
          items:
          - key: tls.crt
            path: tls.crt
          - key: tls.key
            path: tls.key
            mode: 0600  # Restrict key file permissions
      - name: config-files
        configMap:
          name: app-config

---
# 🔍 Secret monitoring and alerting
apiVersion: external-secrets.io/v1alpha1
kind: PushSecret
metadata:
  name: secret-sync-monitoring
  namespace: production
spec:
  deletionPolicy: Delete
  refreshInterval: 10m
  
  secretStoreRefs:
  - name: aws-secrets-manager-store
    kind: SecretStore
  
  selector:
    secret:
      name: monitoring-credentials
  
  data:
  - match:
      secretKey: alert-manager-webhook
      remoteRef:
        remoteKey: prod/monitoring/alertmanager
        property: webhook_url
```

</details>

---

## 🔍 Monitoring and Compliance - Security Observability

### **Why Security Monitoring is Different from Performance Monitoring**

**Security monitoring focus areas:**
- **Anomaly detection** - Unusual access patterns, privilege escalation
- **Compliance reporting** - Audit trails, policy violations
- **Incident response** - Real-time alerting, automated remediation
- **Forensic analysis** - Historical data for investigation

**EKS-specific security monitoring needs:**
- **Control plane activity** - API server calls, authentication events
- **Pod behavior** - Runtime security, network communications
- **IAM usage** - IRSA token usage, permission escalation
- **Network traffic** - East-west traffic, external connections

### 📊 CloudWatch Container Insights - Comprehensive Visibility

**Why CloudWatch integration matters for security:**
- **Native AWS integration** - Works seamlessly with other AWS security services
- **Centralized logging** - All cluster logs in one place
- **Custom metrics** - Security-specific metrics and dashboards
- **Automated alerting** - Real-time response to security events

<details>
<summary>📘 Click to see Security-Focused Monitoring Configuration</summary>

```yaml
# 📈 Security-enhanced CloudWatch agent configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: cwagentconfig-security
  namespace: amazon-cloudwatch
data:
  cwagentconfig.json: |
    {
      "agent": {
        "region": "us-west-2",
        "debug": false,
        "metrics_collection_interval": 30,
        "run_as_user": "cwagent"
      },
      "logs": {
        "metrics_collected": {
          "kubernetes": {
            "cluster_name": "${CLUSTER_NAME}",
            "metrics_collection_interval": 60,
            "enhanced_container_insights": true
          }
        },
        "force_flush_interval": 15,
        "log_stream_name": "eks-security-monitoring",
        "endpoint_override": "logs.us-west-2.amazonaws.com"
      },
      "metrics": {
        "namespace": "EKS/Security",
        "metrics_collected": {
          "cpu": {
            "measurement": [
              "cpu_usage_idle", 
              "cpu_usage_iowait", 
              "cpu_usage_user", 
              "cpu_usage_system",
              "cpu_usage_steal"  # Important for security - detect noisy neighbors
            ],
            "metrics_collection_interval": 30,
            "resources": ["*"],
            "totalcpu": true
          },
          "disk": {
            "measurement": [
              "used_percent", 
              "inodes_free",
              "inodes_used_percent"  # Detect inode exhaustion attacks
            ],
            "metrics_collection_interval": 60,
            "resources": ["*"],
            "drop_device": true
          },
          "diskio": {
            "measurement": [
              "io_time", 
              "read_bytes", 
              "write_bytes", 
              "reads", 
              "writes",
              "iops_in_progress"  # Detect disk-based attacks
            ],
            "metrics_collection_interval": 30,
            "resources": ["*"]
          },
          "mem": {
            "measurement": [
              "mem_used_percent",
              "mem_available_percent",
              "swap_used_percent"  # Detect memory exhaustion
            ],
            "metrics_collection_interval": 30
          },
          "net": {
            "measurement": [
              "bytes_sent",
              "bytes_recv", 
              "packets_sent",
              "packets_recv",
              "drop_in",
              "drop_out",
              "err_in",
              "err_out"  # Network anomaly detection
            ],
            "metrics_collection_interval": 30,
            "resources": ["*"]
          },
          "netstat": {
            "measurement": [
              "tcp_established", 
              "tcp_time_wait",
              "tcp_close_wait",
              "tcp_syn_sent",
              "tcp_syn_recv",
              "udp_socket"  # Connection state monitoring
            ],
            "metrics_collection_interval": 30
          },
          "processes": {
            "measurement": [
              "running",
              "sleeping", 
              "dead",
              "zombies",
              "stopped",
              "total"
            ],
            "metrics_collection_interval": 60
          }
        }
      }
    }

---
# 🚨 Security-focused log collection
apiVersion: logging.coreos.com/v1
kind: ClusterLogForwarder
metadata:
  name: security-log-forwarder
  namespace: openshift-logging
spec:
  outputs:
  - name: cloudwatch-security
    type: cloudwatch
    cloudwatch:
      groupName: /aws/eks/security-logs
      region: us-west-2
    secret:
      name: cloudwatch-credentials
  
  pipelines:
  # Audit logs for compliance
  - name: audit-logs
    inputRefs:
    - audit
    outputRefs:
    - cloudwatch-security
    labels:
      log-type: "audit"
      compliance: "required"
  
  # Container security logs
  - name: container-security
    inputRefs:
    - container
    filterRefs:
    - security-events-filter
    outputRefs:
    - cloudwatch-security
    labels:
      log-type: "security"

---
# 📊 Custom metrics for security monitoring
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-metrics
  namespace: monitoring
data:
  custom-metrics.yaml: |
    # Failed authentication attempts
    - name: failed_auth_attempts
      help: "Number of failed authentication attempts"
      type: counter
      match: '*.authenticator.*FAILED*'
      labels:
        cluster: "${CLUSTER_NAME}"
        source_ip: '$1'
        user: '$2'
    
    # Privilege escalation attempts
    - name: privilege_escalation_attempts
      help: "Attempts to escalate privileges"
      type: counter
      match: '*escalation*denied*'
      labels:
        cluster: "${CLUSTER_NAME}"
        user: '$1'
        namespace: '$2'
    
    # Suspicious network activity
    - name: suspicious_network_connections
      help: "Suspicious outbound network connections"
      type: counter
      match: '*connection*denied*'
      labels:
        cluster: "${CLUSTER_NAME}"
        pod: '$1'
        destination: '$2'

---
# 🎯 Security alerting rules
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: eks-security-alerts
  namespace: monitoring
spec:
  groups:
  - name: eks-security
    rules:
    # High number of failed authentication attempts
    - alert: HighFailedAuthRate
      expr: rate(failed_auth_attempts[5m]) > 10
      for: 2m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "High rate of failed authentication attempts detected"
        description: "Cluster {{ $labels.cluster }} is experiencing {{ $value }} failed auth attempts per second"
    
    # Privilege escalation attempts
    - alert: PrivilegeEscalationAttempt
      expr: increase(privilege_escalation_attempts[1m]) > 0
      for: 0m
      labels:
        severity: critical
        category: security
      annotations:
        summary: "Privilege escalation attempt detected"
        description: "User {{ $labels.user }} attempted privilege escalation in namespace {{ $labels.namespace }}"
    
    # Unusual resource usage (possible cryptomining)
    - alert: AbnormalCPUUsage
      expr: avg_over_time(node_cpu_seconds_total[10m]) > 0.9
      for: 5m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "Abnormal CPU usage detected"
        description: "Node {{ $labels.instance }} showing sustained high CPU usage: {{ $value }}%"
```

</details>

### 🔍 AWS GuardDuty - Threat Detection for EKS

**Why GuardDuty is essential for EKS security:**
- **Behavioral analysis** - Detects anomalous activity in EKS clusters
- **Threat intelligence** - Leverages AWS threat intelligence feeds
- **Machine learning** - Continuously learns normal vs abnormal patterns
- **EKS-specific detections** - Kubernetes audit log analysis

**GuardDuty EKS protection capabilities:**
1. **Malicious IP detection** - Communication with known bad actors
2. **Cryptocurrency mining** - Detects cryptomining activity
3. **Privilege escalation** - Unusual permission requests
4. **Suspicious network activity** - Anomalous traffic patterns

<details>
<summary>📘 Click to see GuardDuty EKS Configuration</summary>

```hcl
# 🛡️ GuardDuty detector with comprehensive EKS protection
resource "aws_guardduty_detector" "eks_security" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"  # Real-time alerting
  
  datasources {
    # S3 data events for compliance
    s3_logs {
      enable = true
    }
    
    # EKS audit logs analysis
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    
    # Malware detection on EKS nodes
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
    
    # Runtime monitoring
    runtime_monitoring {
      enable = true
    }
  }
  
  tags = {
    Name = "EKS-Security-GuardDuty"
    Environment = var.environment
    Purpose = "EKS-Threat-Detection"
  }
}

# 📧 Multi-channel alerting system
resource "aws_sns_topic" "security_alerts" {
  name = "eks-security-alerts"
  
  # Encryption for sensitive security data
  kms_master_key_id = aws_kms_key.eks_secrets.arn
  
  tags = {
    Purpose = "Security-Alerting"
  }
}

# 🚨 Email subscription for critical alerts
resource "aws_sns_topic_subscription" "security_team_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_team_email
  
  filter_policy = jsonencode({
    severity = ["HIGH", "CRITICAL"]
  })
}

# 📱 Slack integration for team notifications
resource "aws_sns_topic_subscription" "slack_webhook" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "https"
  endpoint  = var.slack_webhook_url
}

# ⚡ EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-eks-findings"
  description = "Route GuardDuty EKS findings to security response"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      # High and Critical severity only
      severity = [7.0, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9.0]
      # EKS-specific findings
      service = {
        resourceRole = ["TARGET"]
      }
      # Kubernetes-related findings
      type = [{
        "prefix": "Kubernetes"
      }]
    }
  })
  
  tags = {
    Purpose = "EKS-Security-Response"
  }
}

# 🎯 Multiple targets for comprehensive response
resource "aws_cloudwatch_event_target" "sns_notification" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SecurityTeamNotification"
  arn       = aws_sns_topic.security_alerts.arn
  
  # Transform the event for better readability
  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      title    = "$.detail.title"
      region   = "$.detail.region"
      account  = "$.detail.accountId"
    }
    input_template = <<EOF
{
  "severity": "<severity>",
  "title": "<title>",
  "account": "<account>",
  "region": "<region>",
  "timestamp": "<aws.events.event.ingestion-time>",
  "alert_type": "GuardDuty EKS Finding"
}
EOF
  }
}

# 🤖 Lambda function for automated response
resource "aws_cloudwatch_event_target" "automated_response" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "AutomatedSecurityResponse"
  arn       = aws_lambda_function.security_response.arn
  
  # Pass full event details to Lambda
  input_transformer {
    input_paths = {
      finding_id = "$.detail.id"
      severity   = "$.detail.severity"
      type       = "$.detail.type"
      resource   = "$.detail.resource"
    }
    input_template = <<EOF
{
  "finding_id": "<finding_id>",
  "severity": <severity>,
  "type": "<type>",
  "resource": "<resource>",
  "action": "investigate_and_respond"
}
EOF
  }
}

# 📊 Custom CloudWatch dashboard for GuardDuty findings
resource "aws_cloudwatch_dashboard" "guardduty_eks" {
  dashboard_name = "GuardDuty-EKS-Security"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/GuardDuty", "FindingCount", "DetectorId", aws_guardduty_detector.eks_security.id]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "GuardDuty Findings - EKS Cluster"
        }
      },
      {
        type   = "log"
        width  = 24
        height = 6
        
        properties = {
          query   = "SOURCE '/aws/events/rule/guardduty-eks-findings' | fields @timestamp, detail.severity, detail.title, detail.type | filter detail.severity >= 7.0 | sort @timestamp desc | limit 20"
          region  = var.aws_region
          title   = "Recent High-Severity EKS Security Findings"
        }
      }
    ]
  })
}
```

</details>

### 📋 AWS Config - Continuous Compliance Monitoring

**Why AWS Config is critical for EKS compliance:**
- **Continuous monitoring** - 24/7 compliance checking
- **Configuration drift detection** - Alerts when settings change
- **Compliance reporting** - Automated audit reports
- **Remediation triggers** - Automated fix for policy violations

**EKS-specific compliance requirements:**
1. **Endpoint security** - Private access enforcement
2. **Encryption compliance** - Data protection requirements
3. **Version management** - Security patch compliance
4. **Network security** - VPC and security group validation

<details>
<summary>📘 Click to see AWS Config EKS Rules</summary>

```hcl
# 🔧 AWS Config configuration recorder
resource "aws_config_configuration_recorder" "eks_compliance" {
  name     = "eks-compliance-recorder"
  role_arn = aws_iam_role.config_role.arn
  
  recording_group {
    all_supported = true
    include_global_resource_types = true
    
    # Focus on EKS-related resources
    resource_types = [
      "AWS::EKS::Cluster",
      "AWS::EKS::Nodegroup",
      "AWS::EC2::SecurityGroup",
      "AWS::EC2::VPC",
      "AWS::EC2::Subnet",
      "AWS::IAM::Role",
      "AWS::KMS::Key"
    ]
  }
}

# 📦 Config delivery channel
resource "aws_config_delivery_channel" "eks_compliance" {
  name           = "eks-compliance-delivery"
  s3_bucket_name = aws_s3_bucket.config_bucket.id
  
  # Frequent delivery for security monitoring
  delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

# 🔍 EKS endpoint security rule
resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  name = "eks-endpoint-no-public-access"
  
  description = "Checks whether Amazon EKS cluster endpoint is not publicly accessible"
  
  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }
  
  # Trigger evaluation on configuration changes
  depends_on = [aws_config_configuration_recorder.eks_compliance]
  
  tags = {
    Purpose = "EKS-Network-Security"
    ComplianceFramework = "CIS"
  }
}

# 🔐 EKS secrets encryption rule
resource "aws_config_config_rule" "eks_secrets_encrypted" {
  name = "eks-secrets-encrypted"
  
  description = "Checks whether Amazon EKS clusters have encryption enabled for secrets"
  
  source {
    owner             = "AWS"
    source_identifier = "EKS_SECRETS_ENCRYPTED"
  }
  
  depends_on = [aws_config_configuration_recorder.eks_compliance]
  
  tags = {
    Purpose = "EKS-Data-Protection"
    ComplianceFramework = "SOC2"
  }
}

# 📱 EKS version compliance rule
resource "aws_config_config_rule" "eks_cluster_supported_version" {
  name = "eks-cluster-supported-version"
  
  description = "Checks whether EKS cluster is running a supported Kubernetes version"
  
  source {
    owner             = "AWS"
    source_identifier = "EKS_CLUSTER_SUPPORTED_VERSION"
  }
  
  depends_on = [aws_config_configuration_recorder.eks_compliance]
  
  tags = {
    Purpose = "EKS-Version-Management"
    ComplianceFramework = "Security-Baseline"
  }
}

# 🌐 EKS node group security rule
resource "aws_config_config_rule" "eks_nodegroup_remote_access_disabled" {
  name = "eks-nodegroup-remote-access-disabled"
  
  description = "Checks whether EKS node groups have remote access disabled"
  
  source {
    owner = "AWS"
    source_identifier = "EKS_NODEGROUP_REMOTE_ACCESS_DISABLED"
  }
  
  depends_on = [aws_config_configuration_recorder.eks_compliance]
  
  tags = {
    Purpose = "EKS-Access-Control"
    ComplianceFramework = "CIS"
  }
}

# 🛡️ Custom rule for EKS security groups
resource "aws_config_config_rule" "eks_security_group_compliance" {
  name = "eks-security-group-compliance"
  
  description = "Checks EKS security groups for compliance with security baseline"
  
  source {
    owner                = "AWS"
    source_identifier    = "SECURITY_GROUP_RESTRICTED_COMMON_PORTS"
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
  }
  
  # Parameters for restricted ports
  input_parameters = jsonencode({
    blockedPort1 = "22"    # SSH
    blockedPort2 = "3389"  # RDP
    blockedPort3 = "135"   # RPC
    blockedPort4 = "445"   # SMB
  })
  
  depends_on = [aws_config_configuration_recorder.eks_compliance]
}

# 📊 Config rules dashboard
resource "aws_config_configuration_aggregator" "eks_compliance" {
  name = "eks-compliance-aggregator"
  
  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator_role.arn
  }
  
  tags = {
    Purpose = "EKS-Compliance-Aggregation"
  }
}

# 🚨 Remediation configuration for non-compliant resources
resource "aws_config_remediation_configuration" "eks_endpoint_remediation" {
  config_rule_name = aws_config_config_rule.eks_endpoint_no_public_access.name
  
  resource_type    = "AWS::EKS::Cluster"
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWSConfigRemediation-RemoveEKSEndpointPublicAccess"
  target_version   = "1"
  
  parameter {
    name           = "AutomationAssumeRole"
    static_value   = aws_iam_role.remediation_role.arn
  }
  
  parameter {
    name                = "ClusterName"
    resource_value      = "RESOURCE_ID"
  }
  
  automatic = true
  maximum_automatic_attempts = 3
}

# 📈 CloudWatch alarms for Config compliance
resource "aws_cloudwatch_metric_alarm" "config_compliance_alarm" {
  alarm_name          = "EKS-Config-Compliance-Violations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ComplianceByConfigRule"
  namespace           = "AWS/Config"
  period              = "300"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "This metric monitors EKS Config rule compliance"
  
  dimensions = {
    RuleName = aws_config_config_rule.eks_endpoint_no_public_access.name
    ComplianceType = "NON_COMPLIANT"
  }
  
  alarm_actions = [aws_sns_topic.security_alerts.arn]
  
  tags = {
    Purpose = "EKS-Compliance-Monitoring"
  }
}
```

</details>

---

## 🚨 Security Incident Response - EKS Forensics and Response

### **Why EKS Incident Response is Complex**

**Multi-layer investigation requirements:**
- **Control plane logs** - API server, audit, authenticator logs
- **Data plane analysis** - Node logs, container logs, network traffic
- **AWS service integration** - CloudTrail, VPC Flow Logs, GuardDuty
- **Kubernetes-native investigation** - Pod analysis, RBAC review

**Incident response phases for EKS:**
1. **Detection** - Automated alerting, anomaly detection
2. **Analysis** - Log correlation, forensic investigation
3. **Containment** - Network isolation, pod quarantine
4. **Eradication** - Remove threats, patch vulnerabilities
5. **Recovery** - Restore services, validate security
6. **Lessons learned** - Update runbooks, improve detection

### 🔍 EKS Forensic Investigation Commands

<details>
<summary>📘 Click to see EKS Investigation Commands</summary>

```bash
#!/bin/bash
# 🔍 EKS Security Incident Investigation Toolkit

# Set variables for investigation
CLUSTER_NAME="production-cluster"
START_TIME="2024-01-01T00:00:00Z"
END_TIME="2024-01-01T23:59:59Z"
SUSPICIOUS_IP="203.0.113.100"
SUSPICIOUS_USER="suspicious-user"

echo "🎯 Starting EKS Security Investigation for cluster: $CLUSTER_NAME"

# 1. EKS Control Plane Analysis
echo "📊 Analyzing EKS control plane logs..."

# Check for authentication failures
aws logs filter-log-events \
  --log-group-name "/aws/eks/$CLUSTER_NAME/cluster" \
  --filter-pattern "{ $.verb = \"create\" && $.objectRef.resource = \"tokenreviews\" && $.responseStatus.code = 401 }" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --end-time $(date -d "$END_TIME" +%s)000 \
  --query 'events[*].[eventTime,message]' \
  --output table

# Check for privilege escalation attempts
aws logs filter-log-events \
  --log-group-name "/aws/eks/$CLUSTER_NAME/cluster" \
  --filter-pattern "{ $.verb = \"create\" && ($.objectRef.resource = \"clusterrolebindings\" || $.objectRef.resource = \"rolebindings\") }" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --end-time $(date -d "$END_TIME" +%s)000 \
  --output json > privilege_escalation_attempts.json

# Analyze suspicious API calls
aws logs filter-log-events \
  --log-group-name "/aws/eks/$CLUSTER_NAME/cluster" \
  --filter-pattern "{ $.sourceIPs[0] = \"$SUSPICIOUS_IP\" }" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --end-time $(date -d "$END_TIME" +%s)000 \
  --output json > suspicious_ip_activity.json

# 2. IAM and IRSA Analysis
echo "🔐 Analyzing IAM and IRSA activity..."

# Check for unusual AssumeRoleWithWebIdentity calls
aws logs filter-log-events \
  --log-group-name "CloudTrail/EKSCluster" \
  --filter-pattern "{ $.eventName = \"AssumeRoleWithWebIdentity\" && $.sourceIPAddress != \"eks.amazonaws.com\" }" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --end-time $(date -d "$END_TIME" +%s)000 \
  --query 'events[*].[eventTime,sourceIPAddress,userIdentity.type,responseElements.assumedRoleUser.arn]' \
  --output table

# Analyze service account token usage
aws logs filter-log-events \
  --log-group-name "CloudTrail/EKSCluster" \
  --filter-pattern "{ $.userIdentity.type = \"WebIdentityUser\" && $.errorCode exists }" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --end-time $(date -d "$END_TIME" +%s)000 \
  --output json > failed_irsa_attempts.json

# 3. Network Traffic Analysis
echo "🌐 Analyzing network traffic patterns..."

# Get VPC Flow Logs for EKS cluster VPC
VPC_ID=$(aws eks describe-cluster --name $CLUSTER_NAME --query 'cluster.resourcesVpcConfig.vpcId' --output text)

# Check for unusual outbound connections
aws logs filter-log-events \
  --log-group-name "VPCFlowLogs" \
  --filter-pattern "{ $.srcaddr = \"$SUSPICIOUS_IP\" || $.dstaddr = \"$SUSPICIOUS_IP\" }" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --end-time $(date -d "$END_TIME" +%s)000 \
  --output json > suspicious_network_activity.json

# Analyze connection patterns
aws ec2 describe-flow-logs \
  --filters Name=resource-id,Values=$VPC_ID \
  --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestination]' \
  --output table

# 4. GuardDuty and Security Service Analysis
echo "🛡️ Checking GuardDuty findings..."

# Get GuardDuty detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Check for high-severity findings
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 7.0},
      "updatedAt": {
        "Gte": "'$START_TIME'",
        "Lte": "'$END_TIME'"
      },
      "service.resourceRole": {"Eq": ["TARGET"]}
    }
  }' \
  --output json > guardduty_findings.json

# Get detailed findings
if [ -s guardduty_findings.json ] && [ "$(jq '.FindingIds | length' guardduty_findings.json)" -gt 0 ]; then
  FINDING_IDS=$(jq -r '.FindingIds[]' guardduty_findings.json)
  aws guardduty get-findings \
    --detector-id $DETECTOR_ID \
    --finding-ids $FINDING_IDS \
    --output json > detailed_guardduty_findings.json
fi

# 5. Kubernetes Native Investigation
echo "☸️ Analyzing Kubernetes resources..."

# Check for suspicious pods
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] | 
  select(
    .spec.containers[].image | test("latest|unknown|suspicious") or
    .spec.securityContext.privileged == true or
    .spec.hostNetwork == true or
    .spec.hostPID == true
  ) | 
  "\(.metadata.namespace)/\(.metadata.name): \(.spec.containers[0].image)"
' > suspicious_pods.txt

# Check for unusual RBAC bindings
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | 
  select(.subjects[]?.name == "'$SUSPICIOUS_USER'") |
  "\(.metadata.name): \(.roleRef.name)"
' > suspicious_rbac.txt

# Check for pods with excessive privileges
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(
    .spec.containers[].securityContext.capabilities.add[]? == "SYS_ADMIN" or
    .spec.containers[].securityContext.allowPrivilegeEscalation == true
  ) |
  "\(.metadata.namespace)/\(.metadata.name): Excessive privileges detected"
' > privileged_pods.txt

# 6. Container and Image Analysis
echo "🐳 Analyzing container security..."

# Check running containers for crypto mining indicators
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.status.phase == "Running") |
  "\(.metadata.namespace) \(.metadata.name)"
' | while read namespace pod; do
  echo "Checking $namespace/$pod for suspicious processes..."
  kubectl exec -n $namespace $pod -- ps aux 2>/dev/null | grep -E "(xmrig|minerd|cgminer|bfgminer)" || true
done > crypto_mining_check.txt

# Check for unusual resource usage
kubectl top pods --all-namespaces --sort-by=cpu | head -20 > high_cpu_pods.txt
kubectl top pods --all-namespaces --sort-by=memory | head -20 > high_memory_pods.txt

# 7. Generate Investigation Report
echo "📄 Generating investigation report..."

cat << EOF > investigation_report.md
# EKS Security Incident Investigation Report

**Cluster:** $CLUSTER_NAME
**Investigation Period:** $START_TIME to $END_TIME
**Generated:** $(date)

## Summary of Findings

### Authentication Issues
\`\`\`
$(if [ -s privilege_escalation_attempts.json ]; then jq -r '.events[].message' privilege_escalation_attempts.json | head -10; else echo "No privilege escalation attempts found"; fi)
\`\`\`

### Network Activity
\`\`\`
$(if [ -s suspicious_network_activity.json ]; then jq -r '.events[].message' suspicious_network_activity.json | head -10; else echo "No suspicious network activity found"; fi)
\`\`\`

### GuardDuty Alerts
\`\`\`
$(if [ -s detailed_guardduty_findings.json ]; then jq -r '.Findings[].Title' detailed_guardduty_findings.json; else echo "No GuardDuty findings in time range"; fi)
\`\`\`

### Suspicious Kubernetes Resources
\`\`\`
$(cat suspicious_pods.txt suspicious_rbac.txt privileged_pods.txt 2>/dev/null || echo "No suspicious Kubernetes resources found")
\`\`\`

### Resource Usage Anomalies
\`\`\`
$(head -5 high_cpu_pods.txt high_memory_pods.txt 2>/dev/null || echo "No resource usage anomalies detected")
\`\`\`

## Recommended Actions

1. **Immediate:** Review and potentially revoke suspicious service accounts
2. **Short-term:** Update network policies to restrict suspicious traffic
3. **Long-term:** Implement additional monitoring for detected patterns

## Evidence Files Generated
- privilege_escalation_attempts.json
- suspicious_ip_activity.json
- failed_irsa_attempts.json
- suspicious_network_activity.json
- guardduty_findings.json
- detailed_guardduty_findings.json
- suspicious_pods.txt
- suspicious_rbac.txt
- privileged_pods.txt
- crypto_mining_check.txt
- high_cpu_pods.txt
- high_memory_pods.txt

EOF

echo "✅ Investigation complete. Report saved to investigation_report.md"
echo "📁 All evidence files saved in current directory"
echo "🚨 Review the report and take immediate action on critical findings"

# Optional: Upload evidence to S3 for long-term storage
if [ ! -z "$EVIDENCE_BUCKET" ]; then
  EVIDENCE_DIR="eks-incident-$(date +%Y%m%d-%H%M%S)"
  aws s3 cp . s3://$EVIDENCE_BUCKET/$EVIDENCE_DIR/ --recursive --exclude "*" --include "*.json" --include "*.txt" --include "*.md"
  echo "📦 Evidence uploaded to s3://$EVIDENCE_BUCKET/$EVIDENCE_DIR/"
fi
```

</details>

### 🛡️ Automated Security Response - Incident Response Automation

**Why automation is critical for EKS security:**
- **Speed of response** - Milliseconds matter in security incidents
- **Consistency** - Automated responses reduce human error
- **Scale** - Handle multiple incidents simultaneously
- **24/7 operation** - Security doesn't sleep

**Automated response capabilities:**
1. **Workload isolation** - Quarantine suspicious pods
2. **Network segmentation** - Apply emergency network policies
3. **Access revocation** - Disable compromised service accounts
4. **Evidence collection** - Automatic forensic data gathering
5. **Notification escalation** - Alert appropriate teams

<details>
<summary>📘 Click to see Security Automation Code</summary>

```python
# 🚨 Advanced EKS Security Incident Response Lambda
import boto3
import json
import logging
from datetime import datetime, timedelta
from kubernetes import client, config
import base64
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
eks_client = boto3.client('eks')
sns_client = boto3.client('sns')
sts_client = boto3.client('sts')
ssm_client = boto3.client('ssm')
cloudwatch_client = boto3.client('cloudwatch')

# Configuration from environment variables
CLUSTER_NAME = os.environ['CLUSTER_NAME']
SECURITY_TOPIC_ARN = os.environ['SECURITY_TOPIC_ARN']
INCIDENT_BUCKET = os.environ['INCIDENT_BUCKET']
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

def lambda_handler(event, context):
    """
    Main handler for EKS security incident response
    """
    try:
        logger.info(f"Processing security event: {json.dumps(event)}")
        
        # Parse the event
        if 'detail' in event:  # EventBridge event
            finding = event['detail']
            event_source = event.get('source', 'unknown')
        else:  # Direct invocation
            finding = event
            event_source = 'direct'
        
        # Determine severity and response level
        severity = finding.get('severity', 0)
        finding_type = finding.get('type', 'Unknown')
        
        logger.info(f"Processing finding: {finding_type} with severity {severity}")
        
        # Response based on severity
        if severity >= 8.0:
            # Critical - immediate isolation and full response
            response_level = 'CRITICAL'
            response_actions = execute_critical_response(finding)
        elif severity >= 7.0:
            # High - investigation and targeted response
            response_level = 'HIGH'
            response_actions = execute_high_response(finding)
        elif severity >= 4.0:
            # Medium - monitoring and alerting
            response_level = 'MEDIUM'
            response_actions = execute_medium_response(finding)
        else:
            # Low - log and monitor
            response_level = 'LOW'
            response_actions = execute_low_response(finding)
        
        # Generate response summary
        response_summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'finding_id': finding.get('id', 'unknown'),
            'finding_type': finding_type,
            'severity': severity,
            'response_level': response_level,
            'actions_taken': response_actions,
            'cluster': CLUSTER_NAME,
            'event_source': event_source
        }
        
        # Store incident data
        store_incident_data(finding, response_summary)
        
        # Send notifications
        send_notifications(response_summary, finding)
        
        logger.info(f"Security response completed: {json.dumps(response_summary)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security response executed successfully',
                'response_level': response_level,
                'actions_taken': len(response_actions)
            })
        }
        
    except Exception as e:
        logger.error(f"Error in security response: {str(e)}")
        send_error_notification(str(e), event)
        raise

def execute_critical_response(finding):
    """
    Critical severity response - immediate containment
    """
    actions_taken = []
    
    try:
        # 1. Initialize Kubernetes client
        k8s_client = get_kubernetes_client()
        
        # 2. Isolate affected workloads
        k8s_details = finding.get('service', {}).get('kubernetesDetails', {})
        if k8s_details:
            isolation_result = isolate_kubernetes_workload(k8s_client, k8s_details)
            actions_taken.append(f"Workload isolation: {isolation_result}")
        
        # 3. Revoke suspicious service accounts
        service_account_result = revoke_suspicious_service_accounts(finding)
        if service_account_result:
            actions_taken.append(f"Service account revocation: {service_account_result}")
        
        # 4. Apply emergency network policies
        network_policy_result = apply_emergency_network_policies(k8s_client, k8s_details)
        actions_taken.append(f"Emergency network policies: {network_policy_result}")
        
        # 5. Collect forensic evidence
        evidence_result = collect_forensic_evidence(finding)
        actions_taken.append(f"Evidence collection: {evidence_result}")
        
        # 6. Scale down suspicious deployments
        if k8s_details.get('kubernetesWorkloadDetails'):
            scale_result = scale_down_suspicious_workloads(k8s_client, k8s_details)
            actions_taken.append(f"Workload scaling: {scale_result}")
        
    except Exception as e:
        logger.error(f"Error in critical response: {str(e)}")
        actions_taken.append(f"Error: {str(e)}")
    
    return actions_taken

def execute_high_response(finding):
    """
    High severity response - investigation and targeted response
    """
    actions_taken = []
    
    try:
        # 1. Enhanced monitoring
        monitoring_result = enable_enhanced_monitoring(finding)
        actions_taken.append(f"Enhanced monitoring: {monitoring_result}")
        
        # 2. Investigate related resources
        investigation_result = investigate_related_resources(finding)
        actions_taken.append(f"Resource investigation: {investigation_result}")
        
        # 3. Apply targeted network restrictions
        k8s_client = get_kubernetes_client()
        k8s_details = finding.get('service', {}).get('kubernetesDetails', {})
        if k8s_details:
            network_result = apply_targeted_network_restrictions(k8s_client, k8s_details)
            actions_taken.append(f"Network restrictions: {network_result}")
        
        # 4. Collect evidence
        evidence_result = collect_forensic_evidence(finding)
        actions_taken.append(f"Evidence collection: {evidence_result}")
        
    except Exception as e:
        logger.error(f"Error in high response: {str(e)}")
        actions_taken.append(f"Error: {str(e)}")
    
    return actions_taken

def execute_medium_response(finding):
    """
    Medium severity response - monitoring and alerting
    """
    actions_taken = []
    
    try:
        # 1. Create CloudWatch alarms
        alarm_result = create_monitoring_alarms(finding)
        actions_taken.append(f"Monitoring alarms: {alarm_result}")
        
        # 2. Log detailed information
        logging_result = log_detailed_finding(finding)
        actions_taken.append(f"Detailed logging: {logging_result}")
        
    except Exception as e:
        logger.error(f"Error in medium response: {str(e)}")
        actions_taken.append(f"Error: {str(e)}")
    
    return actions_taken

def execute_low_response(finding):
    """
    Low severity response - basic logging
    """
    actions_taken = []
    
    try:
        # Basic logging
        logging_result = log_finding(finding)
        actions_taken.append(f"Basic logging: {logging_result}")
        
    except Exception as e:
        logger.error(f"Error in low response: {str(e)}")
        actions_taken.append(f"Error: {str(e)}")
    
    return actions_taken

def get_kubernetes_client():
    """
    Get authenticated Kubernetes client for EKS cluster
    """
    # Get cluster configuration
    cluster_info = eks_client.describe_cluster(name=CLUSTER_NAME)
    
    # Configure kubernetes client
    configuration = client.Configuration()
    configuration.host = cluster_info['cluster']['endpoint']
    configuration.verify_ssl = True
    configuration.ssl_ca_cert = base64.b64decode(
        cluster_info['cluster']['certificateAuthority']['data']
    )
    
    # Get authentication token
    token = get_eks_token(CLUSTER_NAME)
    configuration.api_key = {'authorization': token}
    configuration.api_key_prefix = {'authorization': 'Bearer'}
    
    return client.ApiClient(configuration)

def get_eks_token(cluster_name):
    """
    Get EKS authentication token
    """
    # This would typically use aws-iam-authenticator logic
    # For Lambda, we can use STS to get a token
    session_name = f"eks-security-response-{int(datetime.utcnow().timestamp())}"
    response = sts_client.get_session_token(DurationSeconds=3600)
    return base64.b64encode(
        f"k8s-aws-v1.{cluster_name}".encode()
    ).decode()

def isolate_kubernetes_workload(k8s_client, k8s_details):
    """
    Isolate suspicious Kubernetes workload using network policies
    """
    try:
        workload_details = k8s_details.get('kubernetesWorkloadDetails', {})
        namespace = workload_details.get('namespace', 'default')
        workload_name = workload_details.get('name', 'unknown')
        
        # Create isolation network policy
        network_policy = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'NetworkPolicy',
            'metadata': {
                'name': f'isolation-{workload_name}-{int(datetime.utcnow().timestamp())}',
                'namespace': namespace,
                'labels': {
                    'created-by': 'security-automation',
                    'purpose': 'isolation',
                    'incident-response': 'true'
                }
            },
            'spec': {
                'podSelector': {
                    'matchLabels': workload_details.get('labels', {})
                },
                'policyTypes': ['Ingress', 'Egress'],
                'ingress': [],  # Deny all ingress
                'egress': [     # Allow only DNS
                    {
                        'ports': [{'protocol': 'UDP', 'port': 53}],
                        'to': []
                    }
                ]
            }
        }
        
        # Apply the network policy
        networking_v1 = client.NetworkingV1Api(k8s_client)
        networking_v1.create_namespaced_network_policy(
            namespace=namespace,
            body=network_policy
        )
        
        return f"Isolated workload {workload_name} in namespace {namespace}"
        
    except Exception as e:
        logger.error(f"Failed to isolate workload: {str(e)}")
        return f"Failed to isolate workload: {str(e)}"

def revoke_suspicious_service_accounts(finding):
    """
    Revoke or disable suspicious service accounts
    """
    try:
        # Extract service account information from finding
        user_details = finding.get('service', {}).get('userDetails', {})
        if user_details.get('type') == 'WebIdentityUser':
            # This is an IRSA user, we can identify the service account
            user_name = user_details.get('userName', '')
            if 'system:serviceaccount:' in user_name:
                parts = user_name.split(':')
                if len(parts) >= 4:
                    namespace = parts[2]
                    sa_name = parts[3]
                    
                    # Add annotation to disable the service account
                    k8s_client = get_kubernetes_client()
                    core_v1 = client.CoreV1Api(k8s_client)
                    
                    # Get current service account
                    sa = core_v1.read_namespaced_service_account(
                        name=sa_name,
                        namespace=namespace
                    )
                    
                    # Add suspension annotation
                    if not sa.metadata.annotations:
                        sa.metadata.annotations = {}
                    
                    sa.metadata.annotations.update({
                        'security.kubernetes.io/suspended': 'true',
                        'security.kubernetes.io/suspended-reason': 'Security incident',
                        'security.kubernetes.io/suspended-timestamp': datetime.utcnow().isoformat(),
                        'security.kubernetes.io/incident-id': finding.get('id', 'unknown')
                    })
                    
                    # Update service account
                    core_v1.patch_namespaced_service_account(
                        name=sa_name,
                        namespace=namespace,
                        body=sa
                    )
                    
                    return f"Suspended service account {namespace}/{sa_name}"
        
        return "No service account actions required"
        
    except Exception as e:
        logger.error(f"Failed to revoke service accounts: {str(e)}")
        return f"Failed to revoke service accounts: {str(e)}"

def collect_forensic_evidence(finding):
    """
    Collect forensic evidence and store in S3
    """
    try:
        evidence_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'finding': finding,
            'cluster_info': eks_client.describe_cluster(name=CLUSTER_NAME),
            'node_groups': eks_client.list_nodegroups(clusterName=CLUSTER_NAME)
        }
        
        # Store evidence in S3
        s3_client = boto3.client('s3')
        evidence_key = f"forensic-evidence/{datetime.utcnow().strftime('%Y/%m/%d')}/{finding.get('id', 'unknown')}.json"
        
        s3_client.put_object(
            Bucket=INCIDENT_BUCKET,
            Key=evidence_key,
            Body=json.dumps(evidence_data, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        
        return f"Evidence stored at s3://{INCIDENT_BUCKET}/{evidence_key}"
        
    except Exception as e:
        logger.error(f"Failed to collect evidence: {str(e)}")
        return f"Failed to collect evidence: {str(e)}"

def send_notifications(response_summary, finding):
    """
    Send notifications to security teams
    """
    try:
        # Prepare notification message
        message = {
            'default': json.dumps(response_summary, indent=2),
            'email': format_email_notification(response_summary, finding),
            'sms': format_sms_notification(response_summary)
        }
        
        # Send SNS notification
        sns_client.publish(
            TopicArn=SECURITY_TOPIC_ARN,
            Message=json.dumps(message),
            Subject=f"EKS Security Response: {response_summary['response_level']} - {finding.get('type', 'Unknown')}",
            MessageStructure='json'
        )
        
        # Send Slack notification if configured
        if SLACK_WEBHOOK_URL and response_summary['response_level'] in ['CRITICAL', 'HIGH']:
            send_slack_notification(response_summary, finding)
        
    except Exception as e:
        logger.error(f"Failed to send notifications: {str(e)}")

def format_email_notification(response_summary, finding):
    """
    Format email notification
    """
    return f"""
EKS Security Incident Response Report

Cluster: {CLUSTER_NAME}
Incident ID: {finding.get('id', 'Unknown')}
Severity: {response_summary['severity']} ({response_summary['response_level']})
Finding Type: {response_summary['finding_type']}
Timestamp: {response_summary['timestamp']}

Actions Taken:
{chr(10).join(f"- {action}" for action in response_summary['actions_taken'])}

Recommended Next Steps:
- Review incident details in AWS Console
- Validate automated response actions
- Investigate root cause
- Update security policies if needed

This is an automated response. Please review and take additional action as needed.
"""

def send_error_notification(error_message, event):
    """
    Send error notification when response fails
    """
    try:
        error_notification = {
            'timestamp': datetime.utcnow().isoformat(),
            'error': error_message,
            'event': event,
            'cluster': CLUSTER_NAME
        }
        
        sns_client.publish(
            TopicArn=SECURITY_TOPIC_ARN,
            Message=json.dumps(error_notification, indent=2),
            Subject=f"ERROR: EKS Security Response Failed - {CLUSTER_NAME}"
        )
        
    except Exception as e:
        logger.error(f"Failed to send error notification: {str(e)}")
```

</details>

---

## 🎯 EKS Security Interview Questions - Expert-Level Scenarios

### 🤔 Architecture & Design Questions

**Q: How would you design a security architecture for a multi-tenant EKS cluster serving financial services?**

**A:** 🏦 **Enterprise-grade multi-layered security approach:**

**1. Control Plane Isolation Strategy**
- **Private cluster** - Zero internet exposure for API server
- **Customer-managed KMS** - Full control over encryption keys
- **Comprehensive audit logging** - All API calls logged for compliance

**2. Network Security Architecture**
- **Dedicated VPC** with private subnets only
- **VPC endpoints** for all AWS service connectivity  
- **Security groups for pods** - Granular network controls
- **Network policies** - Kubernetes-native microsegmentation

**3. Identity and Access Management**
- **IRSA per tenant** - Isolated AWS permissions
- **Namespace-based RBAC** - Kubernetes access controls
- **Pod Security Standards** - Restricted mode enforced

**4. Data Protection**
- **Encryption at rest** - EBS, EFS, RDS, S3
- **Encryption in transit** - TLS everywhere, service mesh for mTLS
- **External secrets management** - AWS Secrets Manager + External Secrets Operator

**Why this approach works:**
- **Regulatory compliance** - Meets SOC 2, PCI DSS requirements
- **Tenant isolation** - Strong boundaries between customers
- **Audit capability** - Complete trail for investigations
- **Operational efficiency** - Automated security controls

<details>
<summary>📘 Click to see Financial Services Security Architecture</summary>

```yaml
# Financial services EKS security architecture
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: fintech-production
  region: us-east-1
  tags:
    Environment: production
    Compliance: "PCI-DSS,SOC2,GDPR"
    SecurityLevel: maximum
    DataClassification: confidential

# Private cluster configuration
privateCluster:
  enabled: true
  skipEndpointCreation: false
  additionalEndpointServices:
    - com.amazonaws.us-east-1.s3
    - com.amazonaws.us-east-1.secretsmanager
    - com.amazonaws.us-east-1.kms

clusterEndpoint:
  privateAccess: true
  publicAccess: false

# Customer-managed encryption
secretEncryption:
  keyARN: "arn:aws:kms:us-east-1:123456789012:key/fintech-secrets-key"

# Comprehensive logging for compliance
cloudWatch:
  clusterLogging:
    enable: true
    types: ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    logRetentionInDays: 2555  # 7 years for financial compliance

# Multi-tenant node groups
managedNodeGroups:
  # Tier 1: Critical financial systems
  - name: tier1-nodes
    instanceTypes: ["m5.large"]
    minSize: 3
    maxSize: 10
    labels:
      tier: "tier1"
      security-level: "maximum"
      compliance: "pci-dss"
    taints:
      - key: "tier1"
        value: "true"
        effect: "NoSchedule"
    volumeEncrypted: true
    volumeKmsKeyID: "arn:aws:kms:us-east-1:123456789012:key/fintech-ebs-key"
    
  # Tier 2: Standard financial applications
  - name: tier2-nodes
    instanceTypes: ["m5.medium"]
    minSize: 2
    maxSize: 8
    labels:
      tier: "tier2"
      security-level: "high"
    taints:
      - key: "tier2"
        value: "true"
        effect: "NoSchedule"
    volumeEncrypted: true
```

</details>

**Q: Explain the security benefits and implementation challenges of IRSA vs traditional approaches**

**A:** 🔐 **IRSA Security Architecture Analysis:**

**Security Benefits:**

| **Traditional Approach** | **IRSA Approach** | **Security Impact** |
|-------------------------|------------------|--------------------|
| Long-lived access keys | Short-lived tokens (15min-12hr) | **Reduces blast radius** |
| Shared cluster credentials | Per-service account roles | **Principle of least privilege** |
| Manual key rotation | Automatic token refresh | **Eliminates rotation failures** |
| Keys stored in secrets | Token projected by kubelet | **No secrets management** |
| Broad permissions | Granular, conditional policies | **Fine-grained access control** |
| Limited audit trail | Full CloudTrail integration | **Complete accountability** |

**Implementation Challenges:**

1. **Trust Relationship Complexity**
   - OIDC provider setup and thumbprint management
   - Conditional IAM policies with string matching
   - Cross-account access patterns

2. **Token Lifecycle Management**
   - Understanding token expiration and refresh
   - Handling token projection failures
   - Debugging authentication issues

3. **Migration Complexity**
   - Converting existing applications from access keys
   - Testing IAM policy conditions
   - Coordinating AWS SDK version requirements

**Why IRSA is transformative:**
- **Zero-trust security model** - Never trust, always verify
- **Cloud-native integration** - Works seamlessly with AWS services
- **Compliance alignment** - Meets requirements for credential management

**Q: Design a comprehensive secrets rotation strategy for a production EKS environment**

**A:** 🔄 **Enterprise Secrets Rotation Architecture:**

**Strategic Approach:**
1. **External secrets management** - Never store secrets in Kubernetes
2. **Automated rotation** - Lambda-driven rotation with zero downtime
3. **Application-aware rotation** - Graceful handling of credential changes
4. **Monitoring and alerting** - Track rotation success/failure

**Implementation Strategy:**

<details>
<summary>📘 Click to see Complete Secrets Rotation Solution</summary>

```yaml
# 1. External Secrets Operator with rotation monitoring
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: production-secrets-store
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
# 2. Database credentials with automated rotation
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  refreshInterval: 5m  # Check every 5 minutes for changes
  secretStoreRef:
    name: production-secrets-store
    kind: SecretStore
  
  target:
    name: db-credentials
    creationPolicy: Owner
    template:
      type: Opaque
      metadata:
        annotations:
          # Trigger pod restart on secret change
          reloader.stakater.com/match: "true"
      data:
        # Current credentials
        username: "{{ .username }}"
        password: "{{ .password }}"
        # Previous credentials for graceful transition
        username_previous: "{{ .username_previous | default .username }}"
        password_previous: "{{ .password_previous | default .password }}"
        # Connection strings
        primary_url: "postgresql://{{ .username }}:{{ .password }}@{{ .host }}:{{ .port }}/{{ .database }}?sslmode=require"
        fallback_url: "postgresql://{{ .username_previous | default .username }}:{{ .password_previous | default .password }}@{{ .host }}:{{ .port }}/{{ .database }}?sslmode=require"
  
  data:
  - secretKey: username
    remoteRef:
      key: prod/database/primary
      property: username
  - secretKey: password
    remoteRef:
      key: prod/database/primary
      property: password
  - secretKey: username_previous
    remoteRef:
      key: prod/database/primary
      property: previous_username
  - secretKey: password_previous
    remoteRef:
      key: prod/database/primary
      property: previous_password
  - secretKey: host
    remoteRef:
      key: prod/database/primary
      property: host
  - secretKey: port
    remoteRef:
      key: prod/database/primary
      property: port
  - secretKey: database
    remoteRef:
      key: prod/database/primary
      property: database

---
# 3. Application deployment with rotation handling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: financial-app
  namespace: production
  annotations:
    # Automatic restart on secret changes
    reloader.stakater.com/auto: "true"
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: financial-app:v1.2.3
        env:
        # Application handles credential fallback
        - name: DB_PRIMARY_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: primary_url
        - name: DB_FALLBACK_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: fallback_url
        - name: CREDENTIAL_ROTATION_ENABLED
          value: "true"
        
        # Health checks that validate connectivity
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5

---
# 4. Secrets rotation Lambda function configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: secrets-rotation-config
  namespace: security
data:
  rotation-schedule.yaml: |
    databases:
      - name: primary-db
        secret_arn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/database/primary"
        rotation_days: 30
        notification_topic: "arn:aws:sns:us-west-2:123456789012:secrets-rotation-alerts"
      - name: analytics-db
        secret_arn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/database/analytics"
        rotation_days: 60
        notification_topic: "arn:aws:sns:us-west-2:123456789012:secrets-rotation-alerts"
    
    api_keys:
      - name: payment-gateway
        secret_arn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/api/payment"
        rotation_days: 90
        pre_rotation_webhook: "https://api.company.com/webhooks/credential-rotation/prepare"
        post_rotation_webhook: "https://api.company.com/webhooks/credential-rotation/complete"
    
    certificates:
      - name: tls-certificates
        secret_arn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/tls/app-certs"
        rotation_days: 60
        auto_deploy: true
        validation_required: true

---
# 5. Monitoring for rotation events
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: secrets-rotation-monitoring
  namespace: monitoring
spec:
  groups:
  - name: secrets.rotation
    rules:
    - alert: SecretsRotationFailure
      expr: increase(external_secrets_sync_calls_error[5m]) > 0
      for: 1m
      labels:
        severity: critical
        category: security
      annotations:
        summary: "Secrets rotation failed"
        description: "External secrets sync failed {{ $value }} times in the last 5 minutes"
    
    - alert: SecretsNotRotatedRecently
      expr: (time() - external_secrets_last_sync_time) > 86400 * 7  # 7 days
      for: 0m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "Secrets haven't been checked recently"
        description: "Secret {{ $labels.name }} hasn't been synced for over 7 days"
    
    - alert: DatabaseConnectionFailureAfterRotation
      expr: increase(app_database_connection_errors[10m]) > 5
      for: 2m
      labels:
        severity: critical
        category: application
      annotations:
        summary: "Database connection issues detected"
        description: "Possible credential rotation issue - {{ $value }} connection failures"
```

</details>

**Rotation Success Metrics:**
- **Zero downtime** - Applications handle credential changes gracefully
- **Audit compliance** - Complete trail of who rotated what when
- **Failure recovery** - Automatic rollback on rotation failures
- **Monitoring integration** - Real-time alerts on rotation status

---

## 🔧 AWS-Specific Security Tools - EKS Native Integrations

### **Why AWS-Native Security Tools Matter**

**Integration benefits:**
- **Single pane of glass** - All security data in AWS console
- **Unified billing and management** - One vendor relationship
- **Deep integration** - Tools understand AWS constructs natively
- **Compliance alignment** - Built for AWS compliance frameworks

**EKS-specific AWS security tool advantages:**
- **VPC-native networking** - Security groups work with Kubernetes
- **IAM integration** - Native AWS identity and access management
- **CloudTrail visibility** - All API calls logged automatically
- **Cost optimization** - No additional infrastructure to manage

### 🛡️ AWS Load Balancer Controller - Ingress Security

<details>
<summary>📘 Click to see Secure ALB Configuration</summary>

```yaml
# 🌐 Enterprise-grade secure ALB configuration
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: production-app-ingress
  namespace: production
  annotations:
    # 🔒 SSL/TLS Security
    alb.ingress.kubernetes.io/ssl-redirect: '443'  # Force HTTPS
    alb.ingress.kubernetes.io/ssl-policy: 'ELBSecurityPolicy-TLS-1-2-2017-01'  # Modern TLS only
    alb.ingress.kubernetes.io/certificate-arn: |
      arn:aws:acm:us-west-2:123456789012:certificate/primary-cert,
      arn:aws:acm:us-west-2:123456789012:certificate/backup-cert
    
    # 🛡️ Security Headers and Protection
    alb.ingress.kubernetes.io/load-balancer-attributes: |
      routing.http2.enabled=true,
      routing.http.drop_invalid_header_fields.enabled=true,
      routing.http.preserve_host_header.enabled=false,
      routing.http.x_amzn_tls_version_and_cipher_suite.enabled=true,
      routing.http.xff_client_port.enabled=false,
      access_logs.s3.enabled=true,
      access_logs.s3.bucket=security-alb-logs,
      access_logs.s3.prefix=production-app,
      deletion_protection.enabled=true
    
    # 🎯 Target Configuration for Security Groups
    alb.ingress.kubernetes.io/target-type: ip  # Enable security groups for pods
    alb.ingress.kubernetes.io/ip-address-type: ipv4
    
    # 🌐 Network Placement
    alb.ingress.kubernetes.io/subnets: |
      subnet-pub-1a-12345,
      subnet-pub-1b-67890,
      subnet-pub-1c-abcde
    alb.ingress.kubernetes.io/scheme: internet-facing
    
    # 🔐 Security Groups
    alb.ingress.kubernetes.io/security-groups: |
      sg-alb-production-12345,
      sg-web-tier-67890
    
    # 🚦 Health Check Security
    alb.ingress.kubernetes.io/healthcheck-protocol: HTTPS
    alb.ingress.kubernetes.io/healthcheck-port: '443'
    alb.ingress.kubernetes.io/healthcheck-path: /health/ready
    alb.ingress.kubernetes.io/healthcheck-interval-seconds: '30'
    alb.ingress.kubernetes.io/healthcheck-timeout-seconds: '10'
    alb.ingress.kubernetes.io/healthy-threshold-count: '2'
    alb.ingress.kubernetes.io/unhealthy-threshold-count: '3'
    
    # 🔍 Observability
    alb.ingress.kubernetes.io/load-balancer-attributes: |
      access_logs.s3.enabled=true,
      access_logs.s3.bucket=production-alb-logs,
      access_logs.s3.prefix=app-ingress
    
    # 🏷️ Resource Tags
    alb.ingress.kubernetes.io/tags: |
      Environment=production,
      Application=financial-app,
      SecurityLevel=high,
      Compliance="SOC2,PCI-DSS",
      CostCenter=engineering,
      Owner=platform-team

spec:
  ingressClassName: alb
  
  # 🔒 TLS Configuration
  tls:
  - hosts:
    - secure-app.company.com
    - api.company.com
    - admin.company.com
    secretName: app-tls-secret  # Fallback certificate
  
  rules:
  # 🌐 Main application
  - host: secure-app.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 443
  
  # 📱 API endpoints with additional security
  - host: api.company.com
    http:
      paths:
      - path: /v1
        pathType: Prefix
        backend:
          service:
            name: api-v1-service
            port:
              number: 443
      - path: /v2
        pathType: Prefix
        backend:
          service:
            name: api-v2-service
            port:
              number: 443
  
  # 🔐 Admin interface with restricted access
  - host: admin.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: admin-service
            port:
              number: 443

---
# 🛡️ WAF Integration for Application Security
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: waf-protected-ingress
  namespace: production
  annotations:
    # 🔥 AWS WAF Association
    alb.ingress.kubernetes.io/wafv2-acl-arn: |
      arn:aws:wafv2:us-west-2:123456789012:regional/webacl/production-waf/12345678-1234-1234-1234-123456789012
    
    # 🎯 Shield Advanced for DDoS protection
    alb.ingress.kubernetes.io/load-balancer-attributes: |
      routing.http.drop_invalid_header_fields.enabled=true,
      routing.http2.enabled=true
    
    # Additional security annotations
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
    alb.ingress.kubernetes.io/target-type: ip
spec:
  ingressClassName: alb
  rules:
  - host: protected-app.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: protected-service
            port:
              number: 443

---
# 📊 Monitoring for ALB Security
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: alb-security-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: aws-load-balancer-controller
  endpoints:
  - port: webhook-server
    path: /metrics
    interval: 30s

---
# 🚨 ALB Security Alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: alb-security-alerts
  namespace: monitoring
spec:
  groups:
  - name: alb.security
    rules:
    - alert: ALBHighErrorRate
      expr: |
        (
          sum(rate(aws_alb_target_response_time_count{code=~"5.."}[5m])) /
          sum(rate(aws_alb_target_response_time_count[5m]))
        ) * 100 > 5
      for: 5m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "ALB error rate is high"
        description: "ALB {{ $labels.load_balancer }} has {{ $value }}% error rate"
    
    - alert: ALBSuspiciousTrafficPattern
      expr: |
        sum(rate(aws_alb_request_count[1m])) by (load_balancer) > 1000
      for: 2m
      labels:
        severity: critical
        category: security
      annotations:
        summary: "Suspicious traffic pattern detected"
        description: "ALB {{ $labels.load_balancer }} receiving {{ $value }} requests/sec"
    
    - alert: ALBCertificateExpiringSoon
      expr: |
        (aws_alb_certificate_expiry_time - time()) / 86400 < 30
      for: 0m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "ALB certificate expiring soon"
        description: "Certificate for ALB {{ $labels.load_balancer }} expires in {{ $value }} days"
```

</details>

### 🔍 EKS Fargate - Serverless Pod Security

**Why Fargate provides superior security:**
- **Complete isolation** - Each pod runs in separate microVM
- **No shared kernel** - Eliminates container escape risks
- **Immutable infrastructure** - No persistent access to underlying nodes
- **Automatic patching** - AWS handles all OS and runtime updates
- **Zero infrastructure management** - No nodes to secure or maintain

**Fargate security model advantages:**
1. **Pod-level isolation** - Stronger security boundary than node-based isolation
2. **Runtime security** - AWS manages the entire runtime environment
3. **Network isolation** - Each pod gets its own ENI and security groups
4. **Compliance benefits** - Easier to meet regulatory requirements

<details>
<summary>📘 Click to see Fargate Security Configuration</summary>

```yaml
# 🏃 Production-grade Fargate security profile
fargateProfiles:
  # High-security workloads
  - name: secure-workloads-fargate
    selectors:
    - namespace: secure-workloads
      labels:
        compute-type: fargate
        security-level: maximum
        compliance: "pci-dss"
    - namespace: financial-services
      labels:
        workload-type: payment-processing
    
    # 🔒 Security-first configuration
    subnets:
    - subnet-private-secure-1a  # Dedicated secure subnets
    - subnet-private-secure-1b
    - subnet-private-secure-1c
    
    # 🔐 Enhanced pod execution role with minimal permissions
    podExecutionRoleArn: arn:aws:iam::123456789012:role/fargate-secure-execution-role
    
    # 🏷️ Security and compliance tags
    tags:
      SecurityLevel: maximum
      Environment: production
      DataClassification: confidential
      Compliance: "SOC2,PCI-DSS,HIPAA"
      IsolationType: pod-level
      ManagedBy: platform-team
  
  # CI/CD workloads with controlled access
  - name: cicd-fargate
    selectors:
    - namespace: ci-cd
      labels:
        compute-type: fargate
        workload-type: build
    - namespace: jenkins
      labels:
        component: agent
    
    # 🌐 Network configuration for CI/CD
    subnets:
    - subnet-private-cicd-1a
    - subnet-private-cicd-1b
    
    # 🔧 CI/CD specific execution role
    podExecutionRoleArn: arn:aws:iam::123456789012:role/fargate-cicd-execution-role
    
    tags:
      Purpose: ci-cd
      Environment: shared
      SecurityLevel: controlled
  
  # Batch processing with time-limited access
  - name: batch-processing-fargate
    selectors:
    - namespace: batch-jobs
      labels:
        job-type: data-processing
        compute-type: fargate
    
    # 📊 Batch processing subnets with monitoring
    subnets:
    - subnet-private-batch-1a
    - subnet-private-batch-1b
    
    # 📄 Batch-specific execution role with data access
    podExecutionRoleArn: arn:aws:iam::123456789012:role/fargate-batch-execution-role
    
    tags:
      Purpose: batch-processing
      Environment: production
      DataAccess: analytics
      SecurityLevel: controlled

---
# 🔐 Fargate Pod Execution Role with Security Hardening
apiVersion: v1
kind: ConfigMap
metadata:
  name: fargate-execution-role-policy
  namespace: platform
data:
  secure-execution-policy.json: |
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "ECRAccess",
          "Effect": "Allow",
          "Action": [
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage"
          ],
          "Resource": [
            "arn:aws:ecr:us-west-2:123456789012:repository/secure-apps/*"
          ],
          "Condition": {
            "StringEquals": {
              "ecr:ImageTag": ["stable", "release-*"]
            },
            "StringLike": {
              "ecr:ResourceTag/SecurityScan": "passed"
            }
          }
        },
        {
          "Sid": "ECRAuthToken",
          "Effect": "Allow",
          "Action": [
            "ecr:GetAuthorizationToken"
          ],
          "Resource": "*",
          "Condition": {
            "StringEquals": {
              "aws:RequestedRegion": "us-west-2"
            }
          }
        },
        {
          "Sid": "CloudWatchLogs",
          "Effect": "Allow",
          "Action": [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource": [
            "arn:aws:logs:us-west-2:123456789012:log-group:/aws/fargate/secure-workloads:*"
          ]
        },
        {
          "Sid": "DenyDangerousActions",
          "Effect": "Deny",
          "Action": [
            "iam:*",
            "sts:AssumeRole",
            "ec2:*",
            "s3:DeleteBucket",
            "rds:DeleteDBInstance"
          ],
          "Resource": "*"
        }
      ]
    }

---
# 🛡️ Fargate workload with maximum security
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-payment-processor
  namespace: secure-workloads
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-processor
      security-level: maximum
  template:
    metadata:
      labels:
        app: payment-processor
        compute-type: fargate
        security-level: maximum
        compliance: "pci-dss"
      annotations:
        # Force Fargate scheduling
        eks.amazonaws.com/fargate-profile: secure-workloads-fargate
    spec:
      # 🔐 Security context - maximum restrictions
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
        supplementalGroups: [10001]
      
      containers:
      - name: payment-processor
        image: 123456789012.dkr.ecr.us-west-2.amazonaws.com/payment-processor:v2.1.0
        
        # 🔒 Container security context
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          runAsGroup: 10001
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
        
        # 📊 Resource limits for security
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
            ephemeral-storage: "1Gi"
          limits:
            memory: "1Gi"
            cpu: "1000m"
            ephemeral-storage: "2Gi"
        
        # 🔐 Environment variables from secrets
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: payment-db-credentials
              key: connection_string
        - name: ENCRYPTION_KEY_ARN
          value: "arn:aws:kms:us-west-2:123456789012:key/payment-encryption-key"
        
        # 📁 Volume mounts for writable directories
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: app-cache
          mountPath: /app/cache
        - name: app-logs
          mountPath: /app/logs
        
        # 🎯 Health checks
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
      
      # 🗝️ Ephemeral volumes for security
      volumes:
      - name: tmp-volume
        emptyDir:
          medium: Memory
          sizeLimit: 100Mi
      - name: app-cache
        emptyDir:
          sizeLimit: 500Mi
      - name: app-logs
        emptyDir:
          sizeLimit: 200Mi
      
      # 🔍 Node selection for Fargate
      nodeSelector:
        kubernetes.io/arch: amd64
        eks.amazonaws.com/compute-type: fargate
      
      # 🎯 Tolerations for Fargate
      tolerations:
      - key: eks.amazonaws.com/compute-type
        operator: Equal
        value: fargate
        effect: NoSchedule

---
# 📊 Fargate security monitoring
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: fargate-security-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      security-monitoring: fargate
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s

---
# 🚨 Fargate-specific alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: fargate-security-alerts
  namespace: monitoring
spec:
  groups:
  - name: fargate.security
    rules:
    - alert: FargatePodSecurityViolation
      expr: |
        kube_pod_container_status_running{pod=~".*fargate.*"} == 1
        and on(pod) kube_pod_spec_containers_security_context_privileged == 1
      for: 0m
      labels:
        severity: critical
        category: security
      annotations:
        summary: "Privileged container detected on Fargate"
        description: "Pod {{ $labels.pod }} is running privileged container on Fargate"
    
    - alert: FargateHighResourceUsage
      expr: |
        (
          container_memory_usage_bytes{pod=~".*fargate.*"} /
          container_spec_memory_limit_bytes
        ) * 100 > 80
      for: 5m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "Fargate pod using high memory"
        description: "Pod {{ $labels.pod }} using {{ $value }}% of memory limit"
```

</details>

---

## ⚡ EKS Security Quick Reference - Rapid Assessment Tools

### 🔍 Security Assessment Commands - Complete Audit Toolkit

<details>
<summary>📘 Click to see EKS Security Audit Commands</summary>

```bash
#!/bin/bash
# 🔍 EKS Security Assessment Toolkit
# Complete security audit for EKS clusters

CLUSTER_NAME="${1:-production-cluster}"
OUTPUT_DIR="eks-security-audit-$(date +%Y%m%d-%H%M%S)"

echo "🔍 Starting comprehensive EKS security audit for: $CLUSTER_NAME"
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# 1. 🎯 Cluster Configuration Audit
echo "1. Auditing cluster configuration..."
aws eks describe-cluster --name "$CLUSTER_NAME" \
  --query 'cluster.{
    Name: name,
    Version: version,
    PlatformVersion: platformVersion,
    Status: status,
    Endpoint: endpoint,
    EndpointConfig: resourcesVpcConfig,
    Encryption: encryptionConfig,
    Logging: logging.clusterLogging,
    Identity: identity,
    Tags: tags
  }' --output json > cluster-config.json

# Check for security misconfigurations
echo "⚠️  Checking for security issues in cluster config..."
jq -r '
  if .EndpointConfig.endpointPublicAccess == true then
    "WARNING: Public endpoint access enabled"
  else empty end,
  if .Encryption == null then
    "CRITICAL: Secrets encryption not enabled"
  else empty end,
  if .Logging.types | length == 0 then
    "WARNING: Cluster logging not enabled"
  else empty end
' cluster-config.json > cluster-security-findings.txt

# 2. 🔐 IAM and IRSA Analysis
echo "2. Analyzing IAM configuration..."

# Check OIDC provider
OIDC_URL=$(jq -r '.Identity.oidc.issuer' cluster-config.json | sed 's|https://||')
aws iam list-openid-connect-providers \
  --query "OpenIDConnectProviderList[?contains(Arn, '$OIDC_URL')].Arn" \
  --output json > oidc-providers.json

if [ "$(jq length oidc-providers.json)" -eq 0 ]; then
  echo "CRITICAL: No OIDC provider found for IRSA" >> cluster-security-findings.txt
fi

# List all service accounts with IRSA annotations
kubectl get serviceaccounts --all-namespaces -o json | jq -r '
  .items[] |
  select(.metadata.annotations["eks.amazonaws.com/role-arn"] != null) |
  "\(.metadata.namespace)/\(.metadata.name): \(.metadata.annotations["eks.amazonaws.com/role-arn"])"
' > irsa-service-accounts.txt

# 3. 🛡️ Security Group Analysis
echo "3. Analyzing security groups..."
VPC_ID=$(jq -r '.EndpointConfig.vpcId' cluster-config.json)

# Get all security groups related to EKS
aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=*eks*" \
  --query 'SecurityGroups[].{
    GroupId: GroupId,
    GroupName: GroupName,
    Description: Description,
    IngressRules: IpPermissions,
    EgressRules: IpPermissionsEgress,
    Tags: Tags
  }' --output json > security-groups.json

# Check for overly permissive rules
jq -r '
  .[] |
  select(
    .IngressRules[]?.IpRanges[]?.CidrIp == "0.0.0.0/0" or
    .IngressRules[]?.FromPort == 0 and .IngressRules[]?.ToPort == 65535
  ) |
  "WARNING: Security group \(.GroupId) (\(.GroupName)) has overly permissive ingress rules"
' security-groups.json > security-group-findings.txt

# 4. 📊 Node Group Security Assessment
echo "4. Assessing node group security..."

# List all node groups
aws eks list-nodegroups --cluster-name "$CLUSTER_NAME" \
  --query 'nodegroups[]' --output json > nodegroup-names.json

# Detailed analysis of each node group
echo "[]" > nodegroups-detailed.json
for ng in $(jq -r '.[]' nodegroup-names.json); do
  echo "  Analyzing node group: $ng"
  aws eks describe-nodegroup --cluster-name "$CLUSTER_NAME" --nodegroup-name "$ng" \
    --query 'nodegroup.{
      NodegroupName: nodegroupName,
      Status: status,
      InstanceTypes: instanceTypes,
      AmiType: amiType,
      RemoteAccess: remoteAccess,
      SecurityGroups: resources.remoteAccessSecurityGroup,
      Subnets: subnets,
      Tags: tags,
      LaunchTemplate: launchTemplate
    }' --output json > "nodegroup-$ng.json"
  
  # Check for security issues
  if jq -e '.RemoteAccess.ec2SshKey != null' "nodegroup-$ng.json" > /dev/null; then
    echo "WARNING: Node group $ng has SSH access enabled" >> nodegroup-security-findings.txt
  fi
  
  # Merge into detailed file
  jq -s '.[0] + [.[1]]' nodegroups-detailed.json "nodegroup-$ng.json" > temp.json
  mv temp.json nodegroups-detailed.json
done

# 5. 🔒 Add-on Security Assessment
echo "5. Checking EKS add-ons and versions..."

# List installed add-ons
aws eks list-addons --cluster-name "$CLUSTER_NAME" \
  --output json > installed-addons.json

# Check version currency for each add-on
echo "{}" > addon-versions.json
for addon in $(jq -r '.addons[]' installed-addons.json); do
  echo "  Checking $addon versions..."
  
  # Get installed version
  INSTALLED_VERSION=$(aws eks describe-addon --cluster-name "$CLUSTER_NAME" --addon-name "$addon" \
    --query 'addon.addonVersion' --output text)
  
  # Get latest available version
  K8S_VERSION=$(jq -r '.Version' cluster-config.json)
  LATEST_VERSION=$(aws eks describe-addon-versions --addon-name "$addon" \
    --kubernetes-version "$K8S_VERSION" \
    --query 'addons[0].addonVersions[0].addonVersion' --output text)
  
  # Update JSON with version info
  jq --arg addon "$addon" --arg installed "$INSTALLED_VERSION" --arg latest "$LATEST_VERSION" \
    '.[$addon] = {"installed": $installed, "latest": $latest, "outdated": ($installed != $latest)}' \
    addon-versions.json > temp.json
  mv temp.json addon-versions.json
  
  if [ "$INSTALLED_VERSION" != "$LATEST_VERSION" ]; then
    echo "WARNING: Add-on $addon is outdated (installed: $INSTALLED_VERSION, latest: $LATEST_VERSION)" >> addon-security-findings.txt
  fi
done

# 6. ☸️ Kubernetes Security Assessment
echo "6. Analyzing Kubernetes security configuration..."

# Check Pod Security Standards
kubectl get namespaces -o json | jq -r '
  .items[] |
  select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) |
  "WARNING: Namespace \(.metadata.name) does not have Pod Security Standards enforced"
' > pod-security-findings.txt

# Check for privileged pods
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.securityContext.privileged == true or .spec.containers[].securityContext.privileged == true) |
  "CRITICAL: Privileged pod found - \(.metadata.namespace)/\(.metadata.name)"
' > privileged-pods.txt

# Check for pods with host networking
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.hostNetwork == true) |
  "WARNING: Pod with host networking - \(.metadata.namespace)/\(.metadata.name)"
' > host-network-pods.txt

# Check for overly permissive RBAC
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.subjects[]?.name == "system:anonymous" or .subjects[]?.name == "system:unauthenticated") |
  "CRITICAL: ClusterRoleBinding \(.metadata.name) grants permissions to anonymous/unauthenticated users"
' > rbac-findings.txt

# 7. 🌐 Network Security Analysis
echo "7. Analyzing network security..."

# Check for network policies
NETWORK_POLICY_COUNT=$(kubectl get networkpolicies --all-namespaces --no-headers | wc -l)
if [ "$NETWORK_POLICY_COUNT" -eq 0 ]; then
  echo "WARNING: No network policies found in cluster" > network-security-findings.txt
else
  kubectl get networkpolicies --all-namespaces -o json > network-policies.json
fi

# Check for services with type LoadBalancer
kubectl get services --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.type == "LoadBalancer") |
  "INFO: LoadBalancer service found - \(.metadata.namespace)/\(.metadata.name)"
' > loadbalancer-services.txt

# 8. 📊 Generate Security Report
echo "8. Generating security assessment report..."

cat << EOF > security-assessment-report.md
# EKS Security Assessment Report

**Cluster:** $CLUSTER_NAME  
**Assessment Date:** $(date)  
**Audit Version:** 1.0

## Executive Summary

### Critical Findings
\`\`\`
$(grep "CRITICAL:" *-findings.txt *-pods.txt 2>/dev/null | head -10 || echo "No critical findings")
\`\`\`

### Warnings
\`\`\`
$(grep "WARNING:" *-findings.txt 2>/dev/null | head -10 || echo "No warnings")
\`\`\`

## Detailed Findings

### 1. Cluster Configuration
- **Kubernetes Version:** $(jq -r '.Version' cluster-config.json)
- **Platform Version:** $(jq -r '.PlatformVersion' cluster-config.json)
- **Public Endpoint:** $(jq -r '.EndpointConfig.endpointPublicAccess' cluster-config.json)
- **Secrets Encryption:** $(jq -r 'if .Encryption then "Enabled" else "Disabled" end' cluster-config.json)
- **Audit Logging:** $(jq -r '.Logging.types | length' cluster-config.json) log types enabled

### 2. Identity and Access Management
- **OIDC Provider:** $(jq length oidc-providers.json) provider(s) configured
- **Service Accounts with IRSA:** $(wc -l < irsa-service-accounts.txt) accounts

### 3. Network Security
- **Security Groups:** $(jq length security-groups.json) groups analyzed
- **Network Policies:** $NETWORK_POLICY_COUNT policies found
- **LoadBalancer Services:** $(wc -l < loadbalancer-services.txt) services

### 4. Workload Security
- **Privileged Pods:** $(wc -l < privileged-pods.txt) pods
- **Host Network Pods:** $(wc -l < host-network-pods.txt) pods
- **Namespaces without PSS:** $(grep -c "WARNING:" pod-security-findings.txt 2>/dev/null || echo 0) namespaces

### 5. Add-on Security
$(jq -r 'to_entries[] | "- **\(.key):** \(.value.installed) (latest: \(.value.latest))"' addon-versions.json)

## Recommendations

### Immediate Actions Required
$(grep "CRITICAL:" *-findings.txt *-pods.txt 2>/dev/null | sed 's/^/1. /' || echo "No critical issues requiring immediate action")

### Security Improvements
$(grep "WARNING:" *-findings.txt 2>/dev/null | head -5 | sed 's/^/1. /' || echo "No warnings to address")

### Best Practices
1. Enable Pod Security Standards for all namespaces
2. Implement network policies for workload isolation
3. Regular security scanning of container images
4. Keep EKS add-ons updated to latest versions
5. Review and minimize RBAC permissions regularly

## Files Generated
- cluster-config.json: Complete cluster configuration
- security-groups.json: Security group analysis
- nodegroups-detailed.json: Node group configurations
- addon-versions.json: Add-on version comparison
- network-policies.json: Network policy configurations
- Various findings files: Specific security issues identified

---
*This report was generated using automated EKS security assessment tools. Manual review is recommended for complete security validation.*
EOF

echo "✅ Security assessment complete!"
echo "📄 Report saved to: $OUTPUT_DIR/security-assessment-report.md"
echo "📁 All evidence files saved in: $OUTPUT_DIR/"
echo "🔍 Review the report and address critical/warning items"

# Optional: Upload to S3 for centralized storage
if [ ! -z "$SECURITY_BUCKET" ]; then
  aws s3 cp . s3://$SECURITY_BUCKET/eks-security-assessments/$CLUSTER_NAME-$(date +%Y%m%d)/ --recursive
  echo "📦 Assessment uploaded to S3: s3://$SECURITY_BUCKET/eks-security-assessments/$CLUSTER_NAME-$(date +%Y%m%d)/"
fi
```

</details>

### 🏆 EKS Security Checklist - Enterprise Production Standards

#### 🎛️ Control Plane Security
- ✅ **Private endpoint only** - No public internet access to API server
- ✅ **Customer-managed KMS encryption** - Full control over encryption keys
- ✅ **Comprehensive audit logging** - All 5 log types enabled (api, audit, authenticator, controllerManager, scheduler)
- ✅ **Supported Kubernetes version** - Within AWS support window (N-2)
- ✅ **VPC-only communication** - Private subnets with VPC endpoints for AWS services
- ✅ **Control plane logging retention** - Minimum 90 days for compliance

#### 🔐 Identity & Access Management
- ✅ **IRSA for all workloads** - No long-lived credentials in pods
- ✅ **Least privilege RBAC** - Role-based access with minimal permissions
- ✅ **Service account isolation** - One service account per application/microservice
- ✅ **Node instance roles** - Minimal EC2 permissions for worker nodes
- ✅ **OIDC provider configured** - Trust relationship established for token exchange
- ✅ **Cross-account access** - Proper role delegation for multi-account setups
- ✅ **Regular permission auditing** - Quarterly review of IAM roles and policies

#### 🌐 Network Security & Microsegmentation
- ✅ **Defense in depth** - Multiple security group layers (cluster, node, pod)
- ✅ **Zero-trust networking** - Deny-all default with explicit allow rules
- ✅ **VPC Flow Logs enabled** - Complete network traffic visibility
- ✅ **Private subnets only** - No direct internet access for worker nodes
- ✅ **Security groups for pods** - Application-level network controls
- ✅ **Network policies enforced** - Kubernetes-native traffic filtering
- ✅ **Ingress security** - WAF integration, SSL/TLS termination
- ✅ **Egress filtering** - Controlled outbound internet access

#### 📦 Container & Runtime Security
- ✅ **Image vulnerability scanning** - ECR scan on push, admission controllers
- ✅ **Pod Security Standards** - Restricted profile enforced cluster-wide
- ✅ **Runtime security contexts** - Non-root, read-only filesystem, dropped capabilities
- ✅ **Resource quotas** - CPU/memory limits to prevent resource exhaustion
- ✅ **Admission controllers** - OPA/Gatekeeper for policy enforcement
- ✅ **Container image signing** - Cryptographic verification of image integrity
- ✅ **Runtime monitoring** - Behavioral analysis for anomaly detection

#### 🔑 Secrets & Data Protection
- ✅ **External secrets management** - AWS Secrets Manager/Parameter Store integration
- ✅ **Encryption at rest** - EBS, EFS, RDS, S3 with customer-managed keys
- ✅ **Encryption in transit** - TLS 1.2+ everywhere, mTLS for service-to-service
- ✅ **Automatic secrets rotation** - Scheduled rotation with zero downtime
- ✅ **Secrets scanning** - No hardcoded credentials in images or config
- ✅ **Key management** - Proper KMS key policies and access controls

#### 🔍 Security Monitoring & Incident Response
- ✅ **GuardDuty EKS protection** - Behavioral threat detection enabled
- ✅ **AWS Config compliance** - Continuous configuration monitoring
- ✅ **CloudWatch Container Insights** - Comprehensive observability
- ✅ **Security information aggregation** - Centralized logging and alerting
- ✅ **Automated incident response** - Lambda-based response to security events
- ✅ **Forensic capabilities** - Evidence collection and investigation tools
- ✅ **Security metrics and SLAs** - Measurable security objectives

#### 📄 Compliance & Governance
- ✅ **Security baseline enforcement** - CIS benchmarks or equivalent
- ✅ **Regulatory compliance** - SOC 2, PCI DSS, HIPAA as required
- ✅ **Change management** - All security changes tracked and approved
- ✅ **Security training** - Team knowledge of EKS security best practices
- ✅ **Disaster recovery** - Security-validated backup and restore procedures
- ✅ **Third-party integrations** - Security review of all external dependencies

#### 🚀 Operational Security
- ✅ **Infrastructure as Code** - All security configurations version-controlled
- ✅ **Security testing integration** - Security scans in CI/CD pipelines
- ✅ **Regular security assessments** - Quarterly penetration testing
- ✅ **Security runbooks** - Documented incident response procedures
- ✅ **Multi-environment strategy** - Consistent security across dev/staging/prod
- ✅ **Business continuity** - Security maintained during outages/incidents

---

## 🎯 Advanced EKS Security Scenarios - Enterprise Patterns

### 🚨 Multi-Tenant Security - Isolation Strategies

**Why multi-tenancy is complex in EKS:**
- **Shared control plane** - All tenants share the same Kubernetes API server
- **Network isolation challenges** - Preventing cross-tenant communication
- **Resource contention** - Ensuring fair resource allocation
- **Security boundaries** - Strong isolation between tenant workloads

**Multi-tenant isolation patterns:**
1. **Namespace-based** - Soft isolation with RBAC and network policies
2. **Node-based** - Hard isolation with dedicated node groups
3. **Cluster-based** - Complete isolation with separate clusters
4. **Hybrid approach** - Combination based on security requirements

<details>
<summary>📘 Click to see Multi-Tenant Security Architecture</summary>

```yaml
# 🏢 Enterprise multi-tenant EKS configuration
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: multi-tenant-cluster
  region: us-west-2
  tags:
    Purpose: multi-tenant
    SecurityModel: strict-isolation

# Dedicated node groups per tenant with strict isolation
managedNodeGroups:
  # Tier 1 tenant (high security, financial services)
  - name: tenant-finance-nodes
    instanceTypes: ["m5.large"]
    minSize: 2
    maxSize: 10
    
    # 🔐 Tenant-specific labels and taints
    labels:
      tenant: finance
      security-tier: tier1
      compliance: "pci-dss,sox"
      isolation-level: maximum
    
    taints:
      - key: tenant
        value: finance
        effect: NoSchedule
      - key: security-tier
        value: tier1
        effect: NoSchedule
    
    # 🛡️ Dedicated security groups per tenant
    securityGroups:
      attachIDs:
        - sg-tenant-finance-nodes
        - sg-tier1-security
    
    # 🔒 Tenant-specific IAM role with strict permissions
    instanceProfile: arn:aws:iam::123456789012:instance-profile/EKS-Finance-Tenant-Profile
    
    # 💾 Encrypted storage with tenant-specific KMS key
    volumeSize: 100
    volumeType: gp3
    volumeEncrypted: true
    volumeKmsKeyID: arn:aws:kms:us-west-2:123456789012:key/finance-tenant-key
    
    # 🌐 Private subnets for maximum isolation
    subnets:
      - subnet-finance-private-1a
      - subnet-finance-private-1b
    
    tags:
      Tenant: finance
      CostCenter: finance-dept
      DataClassification: confidential

  # Tier 2 tenant (standard security, general business)
  - name: tenant-business-nodes
    instanceTypes: ["m5.medium"]
    minSize: 1
    maxSize: 8
    
    labels:
      tenant: business
      security-tier: tier2
      compliance: "soc2"
      isolation-level: standard
    
    taints:
      - key: tenant
        value: business
        effect: NoSchedule
    
    securityGroups:
      attachIDs:
        - sg-tenant-business-nodes
        - sg-tier2-security
    
    instanceProfile: arn:aws:iam::123456789012:instance-profile/EKS-Business-Tenant-Profile
    
    # Standard encryption for business workloads
    volumeSize: 50
    volumeType: gp3
    volumeEncrypted: true
    volumeKmsKeyID: arn:aws:kms:us-west-2:123456789012:key/business-tenant-key
    
    subnets:
      - subnet-business-private-1a
      - subnet-business-private-1b
    
    tags:
      Tenant: business
      CostCenter: business-dept
      DataClassification: internal

  # Development tenant (controlled access, non-production)
  - name: tenant-dev-nodes
    instanceTypes: ["t3.medium"]
    minSize: 1
    maxSize: 5
    
    labels:
      tenant: development
      security-tier: tier3
      environment: non-production
      isolation-level: basic
    
    taints:
      - key: tenant
        value: development
        effect: NoSchedule
    
    securityGroups:
      attachIDs:
        - sg-tenant-dev-nodes
        - sg-tier3-security
    
    instanceProfile: arn:aws:iam::123456789012:instance-profile/EKS-Dev-Tenant-Profile
    
    # Cost-optimized configuration for development
    volumeSize: 30
    volumeType: gp3
    volumeEncrypted: true
    
    # Mixed instance types for cost savings
    mixedInstancesPolicy:
      instancesDistribution:
        onDemandBaseCapacity: 0
        onDemandPercentageAboveBaseCapacity: 0
        spotAllocationStrategy: diversified
    
    subnets:
      - subnet-dev-private-1a
      - subnet-dev-private-1b
    
    tags:
      Tenant: development
      CostCenter: engineering
      DataClassification: public

---
# 🔐 Tenant-specific namespaces with security policies
apiVersion: v1
kind: Namespace
metadata:
  name: finance-tenant
  labels:
    tenant: finance
    security-tier: tier1
    compliance: "pci-dss,sox"
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
  annotations:
    tenant.kubernetes.io/allowed-users: "finance-team"
    tenant.kubernetes.io/isolation-level: "maximum"
    scheduler.alpha.kubernetes.io/node-selector: "tenant=finance"

---
apiVersion: v1
kind: Namespace
metadata:
  name: business-tenant
  labels:
    tenant: business
    security-tier: tier2
    compliance: "soc2"
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
  annotations:
    tenant.kubernetes.io/allowed-users: "business-team"
    tenant.kubernetes.io/isolation-level: "standard"
    scheduler.alpha.kubernetes.io/node-selector: "tenant=business"

---
# 🌐 Network policies for tenant isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation-policy
  namespace: finance-tenant
spec:
  podSelector: {}  # Apply to all pods in namespace
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow traffic only from same tenant
  - from:
    - namespaceSelector:
        matchLabels:
          tenant: finance
    # Allow traffic from ingress controllers
    - namespaceSelector:
        matchLabels:
          name: ingress-system
  
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
  
  # Allow traffic only to same tenant
  - to:
    - namespaceSelector:
        matchLabels:
          tenant: finance
  
  # Allow access to tenant-specific databases
  - to:
    - namespaceSelector:
        matchLabels:
          name: database-finance
    ports:
    - protocol: TCP
      port: 5432

---
# 🔐 RBAC for tenant isolation
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: finance-tenant
  name: finance-tenant-admin
rules:
# Full access within tenant namespace
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
# Deny access to sensitive cluster resources
- apiGroups: [""]
  resources: ["nodes", "persistentvolumes"]
  verbs: ["get", "list"]
  resourceNames: []  # Explicit deny

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: finance-tenant-admin-binding
  namespace: finance-tenant
subjects:
- kind: User
  name: finance-admin
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: finance-team
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: finance-tenant-admin
  apiGroup: rbac.authorization.k8s.io

---
# 📊 Resource quotas for tenant resource isolation
apiVersion: v1
kind: ResourceQuota
metadata:
  name: finance-tenant-quota
  namespace: finance-tenant
spec:
  hard:
    # Compute resources
    requests.cpu: "20"
    requests.memory: "40Gi"
    limits.cpu: "40"
    limits.memory: "80Gi"
    
    # Storage resources
    requests.storage: "500Gi"
    persistentvolumeclaims: "10"
    
    # Object counts
    count/pods: "100"
    count/services: "20"
    count/secrets: "50"
    count/configmaps: "30"
    
    # Security-related limits
    count/services.loadbalancers: "5"
    count/services.nodeports: "0"  # Deny NodePort services

---
# 🛡️ Tenant-specific security policies with Gatekeeper
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: tenantisolation
spec:
  crd:
    spec:
      names:
        kind: TenantIsolation
      validation:
        properties:
          allowedTenants:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package tenantisolation
        
        violation[{"msg": msg}] {
          required := input.parameters.allowedTenants
          provided := input.review.object.metadata.labels.tenant
          not provided in required
          msg := sprintf("Pod tenant '%v' not in allowed tenants %v", [provided, required])
        }

---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: TenantIsolation
metadata:
  name: finance-tenant-isolation
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["finance-tenant"]
  parameters:
    allowedTenants: ["finance"]
```

</details>

### 🛡️ Zero-Trust Networking - Never Trust, Always Verify

**Zero-trust principles for EKS:**
- **Assume breach** - Design assuming attackers are already inside
- **Verify everything** - Authenticate and authorize every connection
- **Least privilege** - Minimum access required for function
- **Continuous monitoring** - Real-time visibility into all communications

**Implementation strategies:**
1. **Service mesh** - mTLS for all service-to-service communication
2. **Network policies** - Default deny with explicit allow rules
3. **Identity-based access** - Every workload has unique identity
4. **Encryption everywhere** - Data protection at rest and in transit

<details>
<summary>📘 Click to see Zero-Trust Network Configuration</summary>

```yaml
# 🕸️ Istio service mesh for zero-trust networking
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: production-istio
spec:
  values:
    global:
      # Enable strict mTLS cluster-wide
      defaultPodDisruptionBudget:
        enabled: true
      proxy:
        # Security hardening
        privileged: false
        readinessInitialDelaySeconds: 5
      
      # Telemetry for zero-trust monitoring
      defaultConfigVisibilitySettings:
        - providers:
            - prometheus
            - jaeger
        - workloadSelector:
            matchLabels:
              app: istio-proxy
  
  components:
    pilot:
      k8s:
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
        securityContext:
          runAsUser: 1337
          runAsGroup: 1337
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
    
    ingressGateways:
    - name: istio-ingressgateway
      enabled: true
      k8s:
        service:
          type: LoadBalancer
          ports:
          - port: 80
            targetPort: 8080
            name: http2
          - port: 443
            targetPort: 8443
            name: https
        securityContext:
          runAsUser: 1337
          runAsGroup: 1337
          runAsNonRoot: true

---
# 🔒 Strict mTLS policy for entire cluster
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system  # Cluster-wide policy
spec:
  mtls:
    mode: STRICT  # Require mTLS for all traffic

---
# 🚦 Fine-grained authorization policies
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: frontend-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: frontend
      tier: web
  
  # Default deny - must explicitly allow traffic
  action: ALLOW
  rules:
  # Allow traffic from authenticated users via ingress
  - from:
    - source:
        principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/v1/*", "/health"]
    when:
    - key: request.headers[authorization]
      values: ["Bearer *"]  # Require authentication token
    - key: source.ip
      notValues: ["10.0.0.0/8"]  # Block internal network access

---
# 🔐 Database service authorization
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: database-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: postgresql
      tier: database
  
  action: ALLOW
  rules:
  # Only allow access from specific backend services
  - from:
    - source:
        principals: 
        - "cluster.local/ns/production/sa/backend-api"
        - "cluster.local/ns/production/sa/user-service"
    to:
    - operation:
        ports: ["5432"]
    when:
    # Additional conditions for database access
    - key: source.namespace
      values: ["production"]
    - key: connection.tls_version
      values: ["TLSv1_2", "TLSv1_3"]  # Require modern TLS

---
# 🌐 Network segmentation with Calico policies
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: zero-trust-baseline
  namespace: production
spec:
  # Apply to all pods in namespace
  selector: all()
  types:
  - Ingress
  - Egress
  
  ingress:
  # Default deny all ingress
  
  egress:
  # Allow DNS resolution
  - action: Allow
    protocol: UDP
    destination:
      ports:
      - 53
      selector: k8s-app == "kube-dns"
  
  # Allow access to Kubernetes API server
  - action: Allow
    protocol: TCP
    destination:
      ports:
      - 443
      nets:
      - "172.20.0.1/32"  # EKS API server IP

---
# 🔍 Service mesh observability
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: zero-trust-metrics
  namespace: istio-system
spec:
  metrics:
  - providers:
    - name: prometheus
  - overrides:
    - match:
        metric: ALL_METRICS
      tagOverrides:
        # Add security-relevant labels
        source_principal:
          value: "%{SOURCE_PRINCIPAL | 'unknown'}"
        destination_principal:
          value: "%{DESTINATION_PRINCIPAL | 'unknown'}"
        connection_security_policy:
          value: "%{CONNECTION_SECURITY_POLICY | 'unknown'}"
  
  accessLogging:
  - providers:
    - name: otel
  - filter:
      expression: 'response.code >= 400 || connection.security_policy != "mutual_tls"'
  
  tracing:
  - providers:
    - name: jaeger
  - customTags:
      security_policy:
        header:
          name: x-security-policy
      user_identity:
        header:
          name: x-user-id

---
# 🚨 Security monitoring and alerting
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: zero-trust-security-alerts
  namespace: monitoring
spec:
  groups:
  - name: zero-trust.security
    rules:
    # Alert on non-mTLS traffic
    - alert: NonMutualTLSTraffic
      expr: |
        sum(rate(istio_requests_total{connection_security_policy!="mutual_tls"}[5m])) > 0
      for: 1m
      labels:
        severity: critical
        category: security
      annotations:
        summary: "Non-mTLS traffic detected"
        description: "{{ $value }} requests/sec without mutual TLS"
    
    # Alert on authorization failures
    - alert: AuthorizationFailures
      expr: |
        sum(rate(istio_requests_total{response_code="403"}[5m])) > 5
      for: 2m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "High rate of authorization failures"
        description: "{{ $value }} authorization failures/sec"
    
    # Alert on suspicious traffic patterns
    - alert: UnusualTrafficPattern
      expr: |
        (
          sum(rate(istio_requests_total[1m])) by (source_app, destination_app) >
          5 * avg_over_time(sum(rate(istio_requests_total[1m])) by (source_app, destination_app)[24h:1h])
        )
      for: 5m
      labels:
        severity: warning
        category: security
      annotations:
        summary: "Unusual traffic pattern detected"
        description: "Traffic from {{ $labels.source_app }} to {{ $labels.destination_app }} is {{ $value }}x normal"
```

</details>

---

> 💡 **EKS Security Interview Success Strategy**: 
>
> **Technical Depth:** Demonstrate understanding of AWS-native security services integration and how EKS leverages AWS security controls beyond standard Kubernetes. Show knowledge of IRSA, VPC CNI, security groups for pods, and GuardDuty EKS protection.
>
> **Business Value:** Always connect security features to business outcomes - reduced risk, compliance alignment, operational efficiency, and cost optimization. Security isn't just about tools, it's about enabling business growth safely.
>
> **Hands-on Experience:** Be prepared to discuss real-world scenarios, trade-offs, and implementation challenges. Mention specific tools, configurations, and lessons learned from production deployments.
>
> **Continuous Learning:** Show awareness of emerging threats, new AWS security features, and evolving best practices. Security is never "done" - it's an ongoing journey of improvement.

---

**🎯 Key EKS Security Takeaway:**

EKS security is about **layered defense** combining Kubernetes security principles with AWS-native security services. Success requires mastering:

- **Kubernetes fundamentals** - RBAC, Pod Security Standards, network policies
- **AWS-specific features** - IRSA, VPC CNI, security groups for pods, GuardDuty
- **Integration patterns** - How AWS services work together for comprehensive protection
- **Operational excellence** - Monitoring, incident response, and continuous improvement

The most secure EKS environments treat security as a **shared responsibility** between AWS (infrastructure) and customers (configuration), with **defense in depth** as the core strategy. Remember: security enables innovation by building trust - it's not just about protection, it's about enabling business growth in the cloud.