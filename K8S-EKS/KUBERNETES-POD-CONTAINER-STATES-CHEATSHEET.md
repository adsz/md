# Kubernetes Pod and Container States - Complete Cheat Sheet

## Pod Phases

| **Phase** | **Description** | **When It Occurs** | **What It Means** |
|-----------|-----------------|-------------------|-------------------|
| **Pending** | Pod accepted but not running | • Scheduling in progress<br>• Image downloading<br>• Volume mounting | Pod is waiting for resources or dependencies |
| **Running** | Pod bound to node, containers created | At least one container is running | Normal operational state |
| **Succeeded** | All containers terminated successfully | Exit code 0 for all containers | Job/batch workload completed |
| **Failed** | All containers terminated, at least one failed | Non-zero exit code or system error | Pod encountered an error |
| **Unknown** | Pod state cannot be determined | • Node communication lost<br>• Kubelet stopped reporting | Cluster has lost contact with pod |

## Container States

| **State** | **Description** | **Fields** | **Common Causes** |
|-----------|---------------|------------|-------------------|
| **Waiting** | Container not yet running | `reason`: Why waiting<br>`message`: Details | • Image pull<br>• Init containers running<br>• Volume not ready |
| **Running** | Container executing | `startedAt`: Timestamp | Normal operation |
| **Terminated** | Container stopped | `exitCode`: Exit status<br>`reason`: Termination cause<br>`startedAt`: Start time<br>`finishedAt`: End time | • Process completed<br>• Container crashed<br>• OOMKilled |

## Container Restart Reasons

| **Reason** | **Exit Code** | **Description** | **Resolution** |
|------------|---------------|----------------|----------------|
| **OOMKilled** | 137 | Out of Memory | Increase memory limits |
| **Error** | 1 | General errors | Check application logs |
| **Completed** | 0 | Successful completion | Normal for Jobs |
| **ContainerCannotRun** | 125 | Docker daemon error | Check container runtime |
| **DeadlineExceeded** | - | Liveness probe failed | Adjust probe settings |
| **Evicted** | - | Node pressure | Check node resources |

## Pod Conditions

| **Type** | **Status** | **Description** | **Troubleshooting** |
|----------|------------|----------------|---------------------|
| **PodScheduled** | True/False/Unknown | Pod assigned to node | Check scheduler logs, node availability |
| **Ready** | True/False/Unknown | Pod ready to serve requests | Check readiness probes |
| **Initialized** | True/False/Unknown | Init containers completed | Check init container logs |
| **ContainersReady** | True/False/Unknown | All containers ready | Check individual container states |

## Common Pod Status Reasons

| **Status** | **Reason** | **Description** | **Action Required** |
|------------|-----------|----------------|---------------------|
| **Pending** | **ImagePullBackOff** | Can't pull container image | • Check image name/tag<br>• Verify registry credentials<br>• Check network connectivity |
| **Pending** | **ErrImagePull** | Initial image pull failed | Same as ImagePullBackOff |
| **Pending** | **CreateContainerConfigError** | ConfigMap/Secret missing | Create missing resources |
| **Pending** | **Unschedulable** | No nodes match pod requirements | • Check node selectors<br>• Verify resource availability<br>• Review taints/tolerations |
| **Running** | **CrashLoopBackOff** | Container repeatedly crashing | • Check application logs<br>• Review exit codes<br>• Verify configurations |
| **Terminating** | **Stuck Terminating** | Pod won't delete | • Check finalizers<br>• Force delete if necessary |

## Init Container States

| **State** | **Meaning** | **Impact on Main Container** | **Debug Command** |
|-----------|-------------|------------------------------|-------------------|
| **Init:0/2** | First of 2 init containers running | Main containers waiting | `kubectl logs <pod> -c <init-container>` |
| **Init:1/2** | Second init container running | Main containers waiting | Check second init container |
| **Init:Error** | Init container failed | Main containers won't start | Check init container exit code |
| **Init:CrashLoopBackOff** | Init container repeatedly failing | Main containers blocked | Review init container logs |
| **PodInitializing** | Init containers completing | Main containers starting soon | Wait for completion |

## Readiness vs Liveness Probes Impact

| **Probe Type** | **Failed State** | **Pod Status** | **Service Impact** | **Container Restart** |
|----------------|------------------|----------------|--------------------|-----------------------|
| **Readiness** | Not Ready | Running | Removed from service endpoints | No |
| **Liveness** | Unhealthy | Running → Terminating | Temporary unavailability | Yes |
| **Startup** | Not Started | Running | Not added to endpoints | No (delays other probes) |

## Quality of Service (QoS) Classes

| **QoS Class** | **Conditions** | **Eviction Priority** | **Use Case** |
|---------------|----------------|----------------------|--------------|
| **Guaranteed** | • Requests = Limits<br>• Both CPU & Memory set | Lowest (last to evict) | Critical workloads |
| **Burstable** | • Requests < Limits<br>• At least one resource set | Medium | Most applications |
| **BestEffort** | • No requests or limits | Highest (first to evict) | Non-critical, batch jobs |

## Node Pressure Conditions Effect on Pods

| **Node Condition** | **Pod Impact** | **Eviction Order** | **Prevention** |
|--------------------|----------------|-------------------|----------------|
| **MemoryPressure** | BestEffort pods evicted first | BestEffort → Burstable → Guaranteed | Set appropriate memory requests |
| **DiskPressure** | Pods using most disk evicted | Based on disk usage | • Use emptyDir limits<br>• Monitor disk usage |
| **PIDPressure** | Pods creating most processes evicted | Based on PID usage | Limit process creation |
| **NetworkUnavailable** | New pods won't schedule | N/A | Fix network plugin |

## Debugging Commands Quick Reference

| **Command** | **Purpose** | **Example** |
|-------------|------------|-------------|
| `kubectl get pods -o wide` | View pod status with node info | Shows READY, STATUS, RESTARTS |
| `kubectl describe pod <name>` | Detailed pod information | Shows events, conditions, containers |
| `kubectl logs <pod> -c <container>` | Container logs | Add `-p` for previous container |
| `kubectl get events --sort-by='.lastTimestamp'` | Cluster events | Shows scheduling, pulling, killing events |
| `kubectl top pod <name>` | Resource usage | Requires metrics-server |
| `kubectl get pod <name> -o yaml` | Full pod specification | Shows complete state and spec |

## State Transition Diagram

```
[Pending] ──→ [Running] ──→ [Succeeded]
    ↓            ↓  ↑           
    ↓            ↓  └─────┐     
    ↓            ↓        ↓     
    └──────→ [Failed] ←───┘     
                 ↓               
            [Unknown]            
```

## Common Troubleshooting Workflow

| **Step** | **Check** | **Command** | **Next Action** |
|----------|-----------|-------------|-----------------|
| 1 | Pod Status | `kubectl get pods` | Identify problematic state |
| 2 | Pod Events | `kubectl describe pod <name>` | Look for error events |
| 3 | Container Logs | `kubectl logs <pod> --all-containers` | Check application errors |
| 4 | Previous Logs | `kubectl logs <pod> -p` | Review crash reasons |
| 5 | Node Status | `kubectl get nodes` | Verify node health |
| 6 | Resource Usage | `kubectl top nodes/pods` | Check resource constraints |
| 7 | Network Policy | `kubectl get networkpolicy` | Verify connectivity rules |

## Exit Codes Reference

| **Exit Code** | **Meaning** | **Common Cause** | **Resolution** |
|---------------|-------------|------------------|----------------|
| **0** | Success | Normal termination | No action needed |
| **1** | General errors | Application error | Check application logs |
| **125** | Container failed to run | Docker/containerd issue | Check runtime logs |
| **126** | Container command not executable | Permission issue | Fix file permissions |
| **127** | Container command not found | Wrong entrypoint/command | Correct container spec |
| **128+n** | Fatal signal n | Killed by signal | • 137 (128+9): SIGKILL/OOM<br>• 143 (128+15): SIGTERM |

## Best Practices for State Management

| **Practice** | **Implementation** | **Benefit** |
|--------------|-------------------|-------------|
| **Set Resource Limits** | Define requests and limits | Prevents OOMKilled, ensures QoS |
| **Configure Health Probes** | Add liveness, readiness, startup probes | Automatic recovery, proper traffic routing |
| **Use Init Containers** | Separate initialization logic | Clean separation of concerns |
| **Handle SIGTERM** | Graceful shutdown in application | Clean termination, data consistency |
| **Set Termination Grace Period** | Adjust `terminationGracePeriodSeconds` | Adequate cleanup time |
| **Monitor Events** | Set up event monitoring | Early problem detection |
| **Use Pod Disruption Budgets** | Define PDBs for critical apps | Maintains availability during updates |

---

*Note: This cheat sheet covers Kubernetes v1.28+ behavior. Some states and reasons may vary slightly between versions.*