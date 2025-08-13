# 🚀 DevOps Concepts Glossary - Interview Reference

## 🧠 DevOps Philosophy & Culture

### 💡 The DevOps Mindset
**Core Principle**: Breaking down silos between Development and Operations teams.
**Goal**: Faster, more reliable software delivery through collaboration, automation, and shared responsibility.
**Interview tip**: Emphasize culture change over just tools - "DevOps is not a job title, it's a methodology."

### 🔄 Three Ways of DevOps (Gene Kim)
1. **Flow**: Optimize work flowing from Dev → Ops → Customer
2. **Feedback**: Create fast feedback loops from right to left
3. **Continuous Learning**: Culture of experimentation and learning from failures

**Interview example**: "We implemented fast feedback by adding automated testing at every stage, reducing our mean time to detection from hours to minutes."

### 🎯 CALMS Framework
- **Culture**: Collaboration, shared responsibility, blameless post-mortems
- **Automation**: Automate repetitive tasks, reduce human error
- **Lean**: Eliminate waste, optimize flow, small batch sizes
- **Measurement**: Data-driven decisions, monitor everything
- **Sharing**: Knowledge sharing, documentation, cross-training

### 📈 DevOps Transformation Stages
1. **Chaotic**: Manual processes, blame culture, long release cycles
2. **Reactive**: Some automation, basic monitoring, still siloed
3. **Proactive**: CI/CD pipelines, infrastructure as code, collaboration
4. **Managed**: Comprehensive monitoring, self-healing systems
5. **Optimized**: Full automation, predictive analytics, innovation culture

**Interview tip**: Position yourself at stage 3-4 and show examples of moving teams forward.

## ⚙️ Core DevOps & Cloud Concepts

### 🔐 RBAC (Role-Based Access Control)
**What**: Security model that restricts system access based on user roles rather than individual permissions.
**Example**: Developer role can deploy to dev/staging but not prod. SRE role can access all environments.
**Interview tip**: Mention least privilege principle and separation of duties.

### 🏗️ IaC (Infrastructure as Code)
**What**: Managing infrastructure through code instead of manual processes.
**Tools**: Terraform, CloudFormation, Pulumi, CDK
**Benefits**: Version control, repeatability, automation, drift detection
**Interview tip**: Emphasize idempotency and declarative vs imperative approaches.

### 🔄 GitOps
**What**: Operational framework using Git as single source of truth for infrastructure and applications.
**How**: Git commits trigger automated deployments. Rollback = git revert.
**Tools**: ArgoCD, Flux, Jenkins X
**Interview tip**: Mention pull vs push models and reconciliation loops.

### 💥 Blast Radius
**What**: Maximum impact scope when something fails in your infrastructure.
**Mitigation**: Small, isolated components; separate state files; multiple AWS accounts
**Example**: VPC failure in dev doesn't affect prod when properly isolated.

### 🔁 DRY (Don't Repeat Yourself)
**What**: Software principle to reduce code duplication.
**In Terraform**: Use modules, Terragrunt, variables, and locals.
**Benefits**: Easier maintenance, consistency, fewer bugs.

### 💾 Terraform State Management - COMPREHENSIVE GUIDE

#### What is Terraform State?
**Definition**: JSON file that maps Terraform configuration to real-world resources. It's Terraform's "source of truth" about your infrastructure.

**Why State Exists**:
1. **Resource Mapping**: Links resources in config to actual cloud resources
2. **Metadata Storage**: Tracks resource dependencies and properties
3. **Performance**: Caches attribute values to reduce API calls
4. **Collaboration**: Enables team coordination via shared state

#### State File Structure
```json
{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 42,  // Increments with each state change
  "lineage": "uuid",  // Tracks state file history
  "outputs": {},
  "resources": [
    {
      "mode": "managed",  // or "data" for data sources
      "type": "aws_instance",
      "name": "web",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [...]
    }
  ]
}
```

#### Critical State Management Concepts

**1. Remote State Backend**
```hcl
terraform {
  backend "s3" {
    bucket         = "terraform-state-bucket"
    key            = "env/prod/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:..."
    dynamodb_table = "terraform-state-lock"
  }
}
```

**Benefits of Remote State**:
- **Team Collaboration**: Shared access to state
- **State Locking**: Prevents concurrent modifications
- **Encryption**: Protects sensitive data
- **Versioning**: State history and recovery
- **Consistency**: Single source of truth

**2. State Locking**
**Purpose**: Prevents concurrent state modifications that could corrupt state.

**How it Works**:
1. Before any operation, Terraform acquires lock
2. Lock contains info: Who, When, Operation ID
3. Lock released after operation completes
4. If process crashes, lock must be manually released

**DynamoDB for Locking**:
```
Table: terraform-state-lock
Primary Key: LockID (String)
Attributes: Info, Created, TTL
```

**Force Unlock** (Emergency only):
```bash
terraform force-unlock <LOCK_ID>
```

**3. State File Security**

**Sensitive Data in State**:
- Passwords, API keys, certificates
- Private IP addresses
- Database connection strings
- Any resource attributes

**Security Best Practices**:
1. **Never commit to Git**: Use .gitignore
2. **Enable encryption**: At-rest (S3-SSE, KMS) and in-transit (TLS)
3. **Restrict access**: IAM policies, bucket policies
4. **Enable versioning**: S3 versioning for recovery
5. **Audit access**: CloudTrail for state bucket
6. **Separate states**: Per environment, per component

**4. State File Operations**

**Common Commands**:
```bash
# List resources in state
terraform state list

# Show specific resource
terraform state show aws_instance.web

# Move resource within state
terraform state mv aws_instance.old aws_instance.new

# Remove from state (not from cloud!)
terraform state rm aws_instance.web

# Pull current state
terraform state pull > current.tfstate

# Push modified state (DANGEROUS!)
terraform state push modified.tfstate

# Replace provider
terraform state replace-provider hashicorp/aws registry.terraform.io/hashicorp/aws
```

**5. State Import**
Import existing resources into Terraform management:
```bash
# Import EC2 instance
terraform import aws_instance.web i-1234567890abcdef0

# Import with for_each
terraform import 'aws_instance.web["prod"]' i-1234567890abcdef0
```

**Import Workflow**:
1. Write resource configuration
2. Run import command
3. Run `terraform plan` to verify
4. Adjust configuration to match reality
5. Achieve clean plan

**6. Workspace Management**
**Purpose**: Multiple states from same configuration (dev, staging, prod).

```bash
# Create and switch workspace
terraform workspace new prod
terraform workspace select prod
terraform workspace list

# Reference in configuration
resource "aws_instance" "web" {
  instance_type = terraform.workspace == "prod" ? "t3.large" : "t3.micro"
}
```

**Workspace State Storage**:
- Local: `terraform.tfstate.d/<workspace>/`
- S3: `env:/<workspace>/terraform.tfstate`

**7. State Splitting & Combining**

**Why Split State**:
- **Reduce blast radius**: Isolated failure domains
- **Improve performance**: Smaller state files
- **Team ownership**: Different teams manage different components
- **Security**: Separate sensitive resources

**Splitting Strategy**:
```
/infrastructure
  /networking (VPC, Subnets, IGW)
  /compute (EC2, ASG, ALB)
  /data (RDS, ElastiCache, S3)
  /security (IAM, KMS, Secrets)
```

**Using Remote State Data**:
```hcl
data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket = "terraform-state"
    key    = "network/terraform.tfstate"
    region = "eu-west-1"
  }
}

# Use outputs from network state
resource "aws_instance" "web" {
  subnet_id = data.terraform_remote_state.network.outputs.private_subnet_ids[0]
}
```

**8. State Disaster Recovery**

**Backup Strategies**:
1. **S3 Versioning**: Enable on state bucket
2. **Cross-region replication**: Replicate to another region
3. **External backups**: Periodic copies to different account
4. **State snapshots**: Before major changes

**Recovery Procedures**:
```bash
# Recover from S3 version
aws s3api list-object-versions --bucket terraform-state
aws s3api get-object --bucket terraform-state --key terraform.tfstate --version-id <VERSION_ID> recovered.tfstate

# Restore state
terraform state push recovered.tfstate
```

**9. Common State Issues & Solutions**

**Issue: State Lock Stuck**
```bash
# Check who has lock
aws dynamodb get-item --table-name terraform-locks --key '{"LockID":{"S":"bucket/key"}}'

# Force unlock if needed
terraform force-unlock <LOCK_ID>
```

**Issue: State Drift**
```bash
# Detect drift
terraform plan -refresh-only

# Update state from reality
terraform apply -refresh-only
```

**Issue: Corrupted State**
1. Restore from S3 version
2. Or rebuild from terraform import
3. Or use terraform state pull/push with manual fixes

**10. Interview Questions & Answers**

**Q: "Why does Terraform need state?"**
A: "State maps configuration to real resources, stores metadata like dependencies, caches attributes for performance, and enables team collaboration through shared state."

**Q: "How do you handle state in a team environment?"**
A: "We use S3 remote backend with DynamoDB locking to prevent concurrent modifications. State is encrypted with KMS, versioned for recovery, and we use separate state files per environment with strict IAM policies."

**Q: "What happens if state file is lost?"**
A: "First, check S3 versioning for recovery. If truly lost, you can recreate by using terraform import for each resource, though this is time-consuming. Best practice is prevention through backups and versioning."

**Q: "How do you manage state file security?"**
A: "Never commit to Git, enable encryption at-rest and in-transit, use IAM to restrict access, enable CloudTrail auditing, store in private S3 bucket with versioning, and regularly rotate KMS keys."

**Q: "Explain state locking"**
A: "State locking prevents race conditions when multiple users run Terraform simultaneously. We use DynamoDB for distributed locking. Each operation acquires a lock with metadata about who's running what, preventing corruption."

**Q: "How do you organize state for large infrastructure?"**
A: "Split state by component (network, compute, data) and environment. This reduces blast radius, improves performance, and allows team ownership. Components communicate via remote state data sources or parameter store."

**Q: "What's the difference between terraform refresh and plan?"**
A: "Refresh updates state file with real infrastructure status. Plan shows differences between desired configuration and current state. Plan includes an implicit refresh unless disabled with -refresh=false."

#### Best Practices Summary
1. **Always use remote state** for production
2. **Enable state locking** to prevent corruption
3. **Encrypt state files** (contain secrets)
4. **Version state files** for disaster recovery
5. **Split state files** to reduce blast radius
6. **Never manual edit** state unless emergency
7. **Regular backups** before major changes
8. **Monitor state operations** via CloudTrail
9. **Document state structure** for team
10. **Test disaster recovery** procedures

### 🎭 Assume Role Pattern
**What**: AWS security pattern where users assume temporary roles instead of having permanent credentials.
**Benefits**: Enhanced security, audit trail, credential rotation, cross-account access
**Implementation**: User → AssumeRole → Temporary credentials (STS) → Access resources

## ☁️ AWS-Specific Concepts

### 🌐 VPC (Virtual Private Cloud)
**What**: Isolated network within AWS cloud.
**Components**: Subnets, route tables, IGW, NAT Gateway, NACLs, Security Groups
**Interview tip**: Explain difference between public/private/database subnets.

### 👤 IAM (Identity and Access Management)
**Components**: Users, Groups, Roles, Policies
**Best Practice**: Use roles for services, MFA for users, temporary credentials via STS
**Policy Types**: Identity-based, Resource-based, Permission boundaries, SCPs

### 🎫 STS (Security Token Service)
**What**: AWS service providing temporary security credentials.
**Use Cases**: AssumeRole, Federation, Cross-account access
**Duration**: 15 minutes to 12 hours (1 hour default)

### 🔑 KMS (Key Management Service)
**What**: Managed service for creating and controlling encryption keys.
**Use Cases**: S3 encryption, EBS volumes, RDS encryption, Secrets Manager
**Types**: AWS managed keys, Customer managed keys (CMK), AWS owned keys

### ⚓ EKS (Elastic Kubernetes Service)
**What**: Managed Kubernetes service by AWS.
**Components**: Control plane (managed), Worker nodes (EC2/Fargate), VPC networking
**Integration**: IAM for RBAC, ALB for ingress, EBS/EFS for storage

### 🚪 NAT Gateway vs NAT Instance
**NAT Gateway**: AWS-managed, highly available, no maintenance, more expensive
**NAT Instance**: Self-managed EC2, cheaper, requires maintenance, single point of failure
**Use Case**: Allow private subnet resources to reach internet for updates.

### 🔗 VPC Endpoints
**What**: Private connection between VPC and AWS services without internet gateway.
**Types**: Gateway endpoints (S3, DynamoDB), Interface endpoints (most other services)
**Benefits**: Lower latency, reduced NAT costs, enhanced security

## 🛠️ Terraform/Terragrunt Concepts

### 📦 Terraform Modules
**What**: Reusable Terraform configurations.
**Structure**: Root module calls child modules, passing variables
**Best Practice**: Version modules, one module per logical component

### 🎯 Terragrunt
**What**: Thin wrapper for Terraform providing extra tools.
**Benefits**: DRY backend config, dependency management, multi-account support
**Use Cases**: Managing multiple environments, preventing code duplication

### 📡 Remote Backend
**What**: Storing Terraform state outside local filesystem.
**Options**: S3+DynamoDB (AWS), Terraform Cloud, Consul, Azure Storage
**Requirements**: Locking mechanism, encryption, versioning

### 🔌 Provider
**What**: Plugin that Terraform uses to manage resources.
**Examples**: AWS, Azure, GCP, Kubernetes, Helm
**Configuration**: Version constraints, authentication, default tags

### 📊 Data Sources vs Resources
**Resources**: Create, update, delete infrastructure (aws_instance, aws_vpc)
**Data Sources**: Read existing infrastructure (data.aws_ami, data.aws_caller_identity)
**Use Case**: Reference existing resources not managed by current Terraform code.

## 🚀 CI/CD Concepts & Deployment Strategies

### 🔵🟢 Blue-Green Deployment - DETAILED
**What**: Two identical production environments (Blue=current, Green=new), switch traffic between them.

**How it works**:
1. Blue environment serves all production traffic
2. Deploy new version to Green environment
3. Run tests and validations on Green
4. Switch router/load balancer to Green
5. Keep Blue as instant rollback option
6. After validation period, Blue becomes next staging target

**Benefits**:
- **Zero downtime**: Traffic switch is instantaneous
- **Instant rollback**: Just switch back to Blue
- **Full testing**: Test in production-like environment before switch
- **Clean cutover**: No mixed versions

**Challenges**:
- **Cost**: Double infrastructure during deployment
- **Database migrations**: Need backward-compatible changes
- **Stateful services**: Session/cache management during switch
- **Long-running transactions**: May be interrupted

**AWS Implementation**:
```
Route53 (weighted routing) → ALB → Target Groups (Blue/Green)
CodeDeploy with Blue/Green deployments
ECS/EKS with multiple services
Elastic Beanstalk environment swap
```

**Interview Example Answer**:
"We implemented blue-green using Route53 weighted routing policies. During deployment, we'd shift 100% traffic from blue to green after validation. Database migrations were handled separately with backward compatibility for at least one version. This reduced our deployment risk and enabled rollback in under 30 seconds."

### 🐦 Canary Deployment - DETAILED
**What**: Gradually roll out changes to small subset of users/servers before full deployment.

**Canary Patterns**:
1. **Linear**: 10% → 25% → 50% → 100% over time
2. **Exponential**: 1% → 2% → 4% → 8% → 16% → 32% → 64% → 100%
3. **Custom**: Based on business rules (e.g., internal users first)

**Benefits**:
- **Risk mitigation**: Issues affect small percentage
- **Real user testing**: Actual production traffic
- **Gradual rollout**: Time to monitor metrics
- **A/B testing capability**: Compare versions

**Monitoring During Canary**:
- Error rates (4xx, 5xx)
- Latency percentiles (p50, p95, p99)
- Business metrics (conversion, user actions)
- Resource utilization (CPU, memory)
- Custom application metrics

**Rollback Triggers**:
- Error rate > threshold (e.g., 1% increase)
- Latency degradation > 10%
- Business metric drop > defined percentage
- Manual intervention

**Tools & Implementation**:
- **AWS CodeDeploy**: Native canary support
- **Kubernetes**: Flagger, Argo Rollouts
- **Service Mesh**: Istio, AWS App Mesh
- **Feature Flags**: LaunchDarkly, AWS AppConfig

**Interview Example Answer**:
"We used canary deployments with Flagger in Kubernetes, starting with 5% traffic. We monitored error rates, p99 latency, and business KPIs. If any metric exceeded thresholds, automatic rollback triggered. This caught a memory leak that only appeared under production load, preventing a major incident."

### 🌊 Rolling Deployment - DETAILED
**What**: Gradually replace instances with new version one at a time or in batches.

**Strategy Options**:
- **One at a time**: Minimize capacity reduction
- **Half at a time**: Faster but requires overcapacity
- **Custom batch size**: Based on fleet size and risk tolerance

**Process**:
1. Take instance out of service (drain connections)
2. Deploy new version
3. Health checks
4. Return to service
5. Repeat for next instance/batch

**Benefits**:
- **No extra infrastructure**: Cost-effective
- **Configurable pace**: Control rollout speed
- **Gradual validation**: Issues appear gradually

**Challenges**:
- **Mixed versions**: Compatibility required
- **Slow rollback**: Must roll forward or back
- **Capacity reduction**: During deployment
- **Complex for stateful services**

**Best Practices**:
- Maintain N+1 capacity during deployment
- Implement connection draining
- Use health checks before rejoining
- Version compatibility for at least N-1

**Interview Example Answer**:
"We used rolling deployments with ECS, updating 25% of tasks at a time. Connection draining ensured no dropped requests. We maintained backward compatibility for APIs and database schemas across versions. This balanced deployment speed with safety."

### 🔴 Red-Black Deployment
**What**: Similar to blue-green but with immediate cutover and no rollback environment.
**Difference from Blue-Green**: Previous version is terminated after successful deployment.
**Use Case**: When rollback strategy is roll-forward, saving infrastructure costs.

### 🌟 Feature Toggle Deployment
**What**: Deploy code with features disabled, enable via configuration without redeployment.

**Benefits**:
- **Decouple deployment from release**
- **Instant rollback**: Just toggle off
- **A/B testing**: Different features for different users
- **Gradual rollout**: Percentage-based activation

**Implementation**:
- **Simple**: Environment variables, config files
- **Advanced**: Feature flag services (LaunchDarkly, Split.io, AWS AppConfig)

**Interview Example Answer**:
"We separated deployment from release using feature flags. New features deployed dark, then gradually enabled via LaunchDarkly. This allowed us to deploy daily but release features when business was ready, and instantly disable problematic features without rollback."

### 🏗️ Recreate Deployment
**What**: Shut down old version completely, then deploy new version.

**When to Use**:
- Development environments
- When downtime is acceptable
- Major incompatible changes
- Limited resources

**Process**:
1. Stop all old version instances
2. Deploy new version to all instances
3. Start all new instances

**Interview Note**: "We only used recreate strategy in dev environments where downtime was acceptable and we needed to ensure clean state."

### 🎯 Shadow/Dark Deployment
**What**: Deploy new version alongside production, mirror traffic for testing without affecting users.

**How it works**:
- Production traffic duplicated to shadow version
- Shadow responses are discarded
- Compare metrics between versions
- No user impact from shadow errors

**Use Cases**:
- Performance testing with real traffic
- Validating major refactoring
- Testing new infrastructure
- Load testing without affecting users

**Implementation Tools**:
- Istio mirroring
- AWS ALB traffic mirroring
- Custom proxy solutions

### 🚁 A/B Testing Deployment
**What**: Different features/versions for different user segments simultaneously.

**Routing Strategies**:
- User ID hash
- Geographic location
- Device type
- Random assignment
- User preferences/profile

**Metrics to Track**:
- Conversion rates
- User engagement
- Performance metrics
- Error rates per variant

**Statistical Significance**:
- Define sample size needed
- Run for complete business cycles
- Account for seasonality
- Use proper statistical tests

### 📊 Deployment Strategy Selection Matrix

| Strategy | Downtime | Rollback Speed | Cost | Risk | Complexity |
|----------|----------|----------------|------|------|------------|
| Recreate | Yes | Slow | Low | High | Low |
| Rolling | No | Slow | Low | Medium | Medium |
| Blue-Green | No | Instant | High | Low | Medium |
| Canary | No | Fast | Medium | Low | High |
| Feature Flags | No | Instant | Low | Very Low | Medium |

### 🗿 Immutable Infrastructure
**What**: Never update servers after deployment, replace instead.
**Benefits**: Consistency, easier rollback, no configuration drift
**Implementation**: New AMI/container for each deployment, blue-green pattern

## ⚓ Kubernetes Concepts

### 🧑‍🚀 Pods
**What**: Smallest deployable unit in K8s, contains one or more containers.
**Characteristics**: Shared network/storage, ephemeral, scheduled together
**Interview tip**: Explain init containers and sidecar pattern.

### 🔄 Services
**What**: Abstract way to expose pods as network service.
**Types**: ClusterIP (internal), NodePort (external), LoadBalancer (cloud LB), ExternalName
**Discovery**: DNS (service-name.namespace.svc.cluster.local)

### 📮 Ingress
**What**: API object managing external access to services, typically HTTP/HTTPS.
**Features**: SSL termination, name-based virtual hosting, path-based routing
**Controllers**: NGINX, ALB (AWS), Traefik

### 🗃️ ConfigMaps and Secrets
**ConfigMaps**: Store non-sensitive configuration data
**Secrets**: Store sensitive data (base64 encoded, not encrypted by default)
**Best Practice**: Use external secret management (Vault, AWS Secrets Manager)

### 🔐 RBAC in Kubernetes
**Components**: ServiceAccounts, Roles/ClusterRoles, RoleBindings/ClusterRoleBindings
**Integration**: Can map AWS IAM roles to K8s RBAC via IRSA
**Namespace**: Roles are namespace-scoped, ClusterRoles are cluster-wide

## 🔍 Monitoring & Observability

### 🏗️ Three Pillars of Observability
1. **Metrics**: Numeric measurements over time (CPU, memory, request rate)
2. **Logs**: Discrete events (application logs, system logs)
3. **Traces**: Request path through distributed system

### 🔥 Prometheus
**What**: Open-source monitoring system with time-series database.
**Architecture**: Pull-based metrics collection, PromQL query language
**Ecosystem**: Grafana (visualization), AlertManager (alerting)

### 🎯 SLI, SLO, SLA
**SLI** (Service Level Indicator): Metric measuring service performance (latency, error rate)
**SLO** (Service Level Objective): Target for SLI (99.9% uptime)
**SLA** (Service Level Agreement): Contract with consequences for not meeting SLO

### 📊 APM (Application Performance Monitoring)
**What**: Monitoring software application performance and availability.
**Tools**: DataDog, New Relic, AppDynamics, AWS X-Ray
**Metrics**: Response time, throughput, error rate, dependency mapping

## 🔒 Security Concepts

### 🏰 Zero Trust Architecture
**Principle**: Never trust, always verify - no implicit trust based on network location.
**Implementation**: Micro-segmentation, least privilege, continuous verification
**Tools**: Service mesh (Istio), ZTNA solutions, AWS PrivateLink

### ⬅️ Shift Left Security
**What**: Integrate security early in development lifecycle.
**Practices**: SAST in IDE, security unit tests, dependency scanning in CI
**Tools**: SonarQube, Snyk, Checkmarx, AWS CodeGuru

### 🏰 Defense in Depth
**What**: Multiple layers of security controls.
**Layers**: Network, host, application, data, physical
**Example**: WAF + Security Groups + NACLs + IAM + Encryption

### 🤝 mTLS (Mutual TLS)
**What**: Both client and server authenticate each other using certificates.
**Use Case**: Service-to-service communication, zero-trust networking
**Implementation**: Service mesh, API Gateway, load balancers

## 💰 Cost Optimization

### 💸 Reserved Instances vs Savings Plans vs Spot
**Reserved Instances**: 1-3 year commitment for specific instance type, up to 72% discount
**Savings Plans**: Flexible commitment to compute usage, up to 66% discount
**Spot Instances**: Unused EC2 capacity, up to 90% discount but can be terminated

### 🏷️ Tagging Strategy
**Purpose**: Cost allocation, automation, compliance, operations
**Best Practice**: Mandatory tags (Environment, Owner, CostCenter, Project)
**Enforcement**: AWS Organizations SCPs, Tag Policies, Config Rules

### 📎 Right-Sizing
**What**: Matching instance types to actual workload requirements.
**Tools**: AWS Compute Optimizer, CloudWatch metrics, Cost Explorer
**Strategy**: Start small and scale up based on metrics, not assumptions

## 🏢 Modern Architecture Patterns

### 🧩 Microservices
**What**: Application as suite of small, independently deployable services.
**Benefits**: Independent scaling, technology diversity, fault isolation
**Challenges**: Distributed system complexity, network latency, data consistency

### 🕸️ Service Mesh
**What**: Infrastructure layer handling service-to-service communication.
**Features**: Traffic management, security (mTLS), observability
**Popular**: Istio, Linkerd, AWS App Mesh, Consul Connect

### ⚡ Event-Driven Architecture
**What**: Services communicate through events rather than direct calls.
**Components**: Event producers, routers (event bus), consumers
**AWS Services**: EventBridge, SNS/SQS, Kinesis, MSK (Kafka)

### ⚡ Serverless
**What**: Running code without managing servers.
**AWS Services**: Lambda (compute), API Gateway (APIs), DynamoDB (database)
**Benefits**: No server management, automatic scaling, pay-per-use
**Challenges**: Vendor lock-in, cold starts, debugging complexity

## 💬 Interview Power Phrases

### When discussing experience:
- "In my previous role, I implemented..."
- "I reduced costs by 40% through..."
- "I improved deployment frequency from weekly to multiple times per day..."

### When explaining decisions:
- "We chose X over Y because of [specific business/technical reason]..."
- "The trade-off we considered was..."
- "To mitigate the risk, we implemented..."

### When discussing problems:
- "The root cause analysis revealed..."
- "We implemented a post-mortem process that..."
- "The lessons learned led us to..."

### Red flags to avoid:
- Never say: "We always do it this way"
- Never say: "I don't know" (say: "I would research/consult documentation")
- Never blame: Previous employer, team members, or tools

## 📈 Key Metrics to Know

### 🚀 Deployment Metrics
- **Deployment Frequency**: How often code deploys to production
- **Lead Time**: Time from code commit to production
- **MTTR** (Mean Time To Recovery): Average time to recover from failure
- **Change Failure Rate**: Percentage of deployments causing failures

### 🖥️ System Metrics
- **RPO** (Recovery Point Objective): Maximum acceptable data loss
- **RTO** (Recovery Time Objective): Maximum acceptable downtime
- **MTTD** (Mean Time To Detect): Time to identify an issue
- **MTBF** (Mean Time Between Failures): Average time between system failures

### 💰 Cost Metrics
- **TCO** (Total Cost of Ownership): All costs of owning/operating
- **ROI** (Return on Investment): Benefit gained from investment
- **FinOps**: Practice of bringing financial accountability to cloud

## 🎭 Common Interview Scenarios

### "How would you handle a production outage?"
1. Incident response process (PagerDuty alert)
2. Assemble incident team, assign roles
3. Communicate status to stakeholders
4. Investigate and mitigate (rollback if needed)
5. Post-mortem within 48 hours (blameless)
6. Action items to prevent recurrence

### "Design a highly available web application"
1. Multi-AZ deployment across 3 AZs
2. Auto-scaling groups with health checks
3. Load balancer (ALB/NLB) with connection draining
4. RDS Multi-AZ or Aurora for database
5. CloudFront CDN for static content
6. Route53 with health checks and failover

### "How do you secure AWS infrastructure?"
1. Identity: MFA, IAM roles over users, temporary credentials
2. Network: Private subnets, NACLs, Security Groups, VPC endpoints
3. Data: Encryption at rest (KMS) and in transit (TLS)
4. Monitoring: CloudTrail, GuardDuty, Security Hub
5. Compliance: Config Rules, AWS Organizations SCPs

## 🛠️ Technologies to Name-Drop

### Trendy but practical:
- **GitOps**: ArgoCD, Flux
- **Policy as Code**: OPA (Open Policy Agent), Sentinel
- **Chaos Engineering**: Chaos Monkey, Gremlin
- **Progressive Delivery**: Flagger, Argo Rollouts

### Shows depth of knowledge:
- **eBPF**: For observability without instrumentation
- **WASM**: For portable, secure edge computing
- **CrossPlane**: Kubernetes-native infrastructure management
- **Backstage**: Developer portal platform

### Enterprise favorites:
- **ServiceNow**: For change management integration
- **Splunk/ELK**: For log aggregation
- **HashiCorp Stack**: Terraform, Vault, Consul, Nomad
- **Datadog/New Relic**: For APM and observability

## ✅ DevOps Best Practices & Patterns

### 📜 The Twelve-Factor App Methodology
**Purpose**: Guidelines for building scalable, maintainable applications.
**Key Factors**: 
1. **Codebase**: One codebase tracked in revision control
2. **Dependencies**: Explicitly declare and isolate dependencies
3. **Config**: Store config in environment variables
4. **Backing services**: Treat backing services as attached resources
5. **Build, release, run**: Strictly separate build and run stages
6. **Processes**: Execute app as one or more stateless processes
7. **Port binding**: Export services via port binding
8. **Concurrency**: Scale out via the process model
9. **Disposability**: Fast startup and graceful shutdown
10. **Dev/prod parity**: Keep development, staging, and production as similar as possible
11. **Logs**: Treat logs as event streams
12. **Admin processes**: Run admin/management tasks as one-off processes

**Interview tip**: Mention specific examples like "We implemented factor 3 by using AWS Parameter Store for configuration management."

### 🏠 Infrastructure Design Patterns

#### 🏢 Multi-Tier Architecture
**Pattern**: Separate application into distinct layers
- **Presentation Tier**: Web servers, load balancers
- **Application Tier**: Application servers, business logic
- **Data Tier**: Databases, caches, message queues
**Benefits**: Scalability, maintainability, security isolation

#### 🎡 Hub and Spoke Network
**Pattern**: Central hub connects to multiple spoke networks
**AWS Implementation**: Transit Gateway connecting multiple VPCs
**Use Case**: Multi-account architecture, shared services

#### ⚡ Circuit Breaker Pattern
**Problem**: Cascading failures in distributed systems
**Solution**: Automatically stop calling failing services
**Implementation**: Netflix Hystrix, AWS X-Ray, Service Mesh
**Interview tip**: "We implemented circuit breakers to prevent our payment service failures from affecting the entire checkout flow."

### 🚢 Bulkhead Pattern
**Concept**: Isolate resources to prevent total system failure
**Example**: Separate thread pools for different operations
**AWS**: Separate Auto Scaling Groups for different services

### 🏥 Platform Engineering Concepts

#### 🔧 Internal Developer Platform (IDP)
**What**: Self-service platform providing developers with tools and infrastructure
**Components**: CI/CD pipelines, environment provisioning, monitoring dashboards
**Benefits**: Reduced cognitive load, faster development cycles, standardization
**Tools**: Backstage, Port, Humanitec

#### ✨ Golden Path
**Concept**: The well-paved, easy path for common developer tasks
**Example**: Template for spinning up new microservices with all best practices built-in
**Interview example**: "We created golden paths that reduced new service setup from 2 weeks to 2 hours."

#### 👨‍💻 Developer Experience (DevEx)
**Focus**: Making developers productive and happy
**Metrics**: Build times, deployment frequency, time to first commit
**Tools**: GitHub Codespaces, Gitpod, devcontainers

### 🔧 Reliability Engineering Patterns

#### 🌪️ Chaos Engineering Principles
1. **Build hypothesis** around steady state behavior
2. **Vary real-world events** (server crashes, network failures)
3. **Run experiments** in production (safely)
4. **Automate** experiments and rollback
5. **Minimize blast radius** of experiments

**Netflix Example**: Chaos Monkey randomly terminates instances
**Interview tip**: "We started with game days, then automated chaos testing to improve our system resilience."

#### 📋 Error Budget Methodology
**Concept**: Treat reliability as a feature with associated costs
**Calculation**: Error Budget = (1 - SLO) × Time Period
**Example**: 99.9% SLO = 0.1% error budget = 43.2 minutes downtime/month
**Policy**: If error budget is exhausted, pause feature releases until reliability improves

#### 📚 Runbook Automation
**Evolution**: Manual runbooks → Automated runbooks → Self-healing systems
**Tools**: Ansible runbooks, AWS Systems Manager, Kubernetes operators
**Best Practice**: Every alert should have a corresponding runbook

### 🔒 DevSecOps Integration

#### ⬅️ Shift-Left Security
**Principle**: Integrate security early in development lifecycle
**Implementation**:
- **IDE**: Security plugins (SonarLint, Snyk)
- **Pre-commit**: Security hooks (git-secrets, detect-secrets)
- **CI Pipeline**: SAST, DAST, dependency scanning
- **Infrastructure**: Policy as Code (OPA, Sentinel)

#### 🏰 Zero Trust Security Model
**Principle**: Never trust, always verify
**Implementation**:
- **Identity**: Strong authentication (MFA, certificates)
- **Device**: Device compliance checks
- **Network**: Micro-segmentation, encrypted traffic
- **Application**: Application-level security
- **Data**: Data classification and encryption

#### 📄 Compliance as Code
**Concept**: Automate compliance checks and reporting
**Tools**: AWS Config, Chef InSpec, Open Policy Agent
**Benefits**: Continuous compliance, audit readiness, reduced manual effort

### 👥 Team Topologies & Conway's Law

#### 🗣️ Conway's Law
**Statement**: "Organizations design systems that mirror their communication structure"
**Implication**: Team structure directly impacts software architecture
**Solution**: Design team structure to match desired architecture

#### 🏢 Team Topologies (Matthew Skelton)
1. **Stream-aligned teams**: Deliver value streams to customers
2. **Enabling teams**: Help stream-aligned teams overcome obstacles
3. **Complicated subsystem teams**: Build specialized subsystems
4. **Platform teams**: Provide internal services to other teams

**Interview tip**: "We restructured our teams around business capabilities rather than technical layers, which improved our delivery speed by 40%."

### 🚀 Advanced DevOps Patterns

#### 🏴 Feature Flags/Toggles
**Purpose**: Decouple deployment from release
**Types**: 
- **Release toggles**: Turn features on/off
- **Experiment toggles**: A/B testing
- **Ops toggles**: Circuit breakers
- **Permission toggles**: Role-based features

#### 🗂 Database DevOps
**Challenges**: Schema migrations, data versioning, zero-downtime deployments
**Patterns**: Blue-green database, expand-contract pattern, feature toggles for schema changes
**Tools**: Flyway, Liquibase, AWS Database Migration Service

#### 🌍 Multi-Region Patterns
**Active-Passive**: One region serves traffic, others on standby
**Active-Active**: Multiple regions serve traffic simultaneously
**Considerations**: Data consistency, latency, costs, compliance

### ⚡ Performance & Optimization

#### 🏃 Load Testing Strategies
**Types**:
- **Load testing**: Expected normal load
- **Stress testing**: Beyond normal capacity
- **Spike testing**: Sudden load increases
- **Volume testing**: Large amounts of data
- **Endurance testing**: Extended periods

**Tools**: JMeter, k6, AWS Load Testing, Artillery

#### 💰 Caching Strategies
**Levels**: Browser, CDN, reverse proxy, application, database
**Patterns**: Cache-aside, write-through, write-behind, refresh-ahead
**Tools**: Redis, Memcached, AWS ElastiCache, CloudFront

#### 🗂 Database Optimization
**Patterns**: Read replicas, sharding, connection pooling, query optimization
**Monitoring**: Slow query logs, connection metrics, lock waits
**AWS**: RDS Performance Insights, Aurora Serverless

## 👑 Leadership & Communication Skills

### 🔍 Blameless Post-Mortems
**Purpose**: Learn from failures without blame
**Process**:
1. Timeline of events
2. Root cause analysis (5 whys)
3. Action items with owners
4. Follow-up review

**Key phrase**: "We treat failures as learning opportunities, not blame opportunities."

### 💳 Managing Technical Debt
**Visualization**: Technical debt quadrant (Reckless vs Prudent, Deliberate vs Inadvertent)
**Strategy**: 
- Track debt in backlog
- Allocate time (20% sprint capacity)
- Business impact communication

**Interview example**: "I helped prioritize technical debt by quantifying the business impact - our deployment time reduction saved 2 developer hours per week."

### 🗣️ Stakeholder Communication
**Technical to Business Translation**: 
- Focus on business outcomes, not technical details
- Use metrics that matter to business (uptime, performance, cost)
- Provide options with trade-offs

**Example**: Instead of "We need to migrate to microservices," say "We can improve our deployment frequency from monthly to weekly by restructuring our application, which will help us respond faster to customer needs."

### 🔄 Change Management
**Kotter's 8-Step Process**:
1. Create urgency
2. Form a guiding coalition
3. Develop vision and strategy
4. Communicate the vision
5. Empower broad-based action
6. Generate short-term wins
7. Sustain acceleration
8. Institute change

**DevOps Application**: Use this framework to drive cultural transformation initiatives.

## 🔮 Modern Industry Trends

### 💰 FinOps (Financial Operations)
**Purpose**: Bring financial accountability to cloud spending
**Practices**: Cost allocation, budgets, forecasting, optimization recommendations
**Tools**: AWS Cost Explorer, CloudHealth, Spot.io
**KPIs**: Cost per customer, cost per transaction, cost optimization percentage

### 🌱 Green DevOps / Sustainable IT
**Focus**: Reduce environmental impact of IT operations
**Practices**: 
- Right-sizing resources
- Serverless computing
- Renewable energy data centers
- Carbon-aware scheduling

**Interview trend**: Shows awareness of broader business concerns beyond just technology.

### 🤖 AI/ML Operations (MLOps)
**Challenges**: Model versioning, data drift, model monitoring, A/B testing for models
**Tools**: MLflow, Kubeflow, AWS SageMaker, DVC
**Patterns**: Feature stores, model registries, automated retraining

### 🌐 Edge Computing & IoT
**Challenges**: Distributed deployments, network constraints, security
**Patterns**: Edge-native applications, local data processing, selective cloud sync
**Tools**: AWS IoT Greengrass, Azure IoT Edge, Google Cloud IoT

Remember: Don't just memorize - understand the WHY behind each concept and be ready to discuss trade-offs and real-world applications. Focus on business outcomes and demonstrate how technical decisions drive business value.