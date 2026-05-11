# Cilium Hybrid Routing: IPCache SkipTunnel 设计方案

## 1. 问题诊断

### 1.1 当前行为

Hybrid routing 的 subnet topology 同时被 Go 控制面和 BPF 数据面使用，但两者看到的是不同层面的 IP：

- **Go 侧** (`pkg/datapath/linux/node.go:925-926`)：用**节点 underlay IP** 查 subnet map → 匹配节点 CIDR → 正确安装直连路由
- **BPF 侧** (`bpf/bpf_lxc.c:1461-1462`, `bpf/bpf_host.c:824-825`)：用**包的 src/dst IP**（Pod IP）查 subnet map → Pod IP 不在节点 CIDR 中 → 返回 0 → same_subnet_id 永远为 false

### 1.2 影响

`same_subnet_id == false` 导致：

| 决策点 | 代码位置 | 期望行为 | 实际行为 |
|--------|----------|----------|----------|
| Tunnel skip | `bpf_host.c:829` `bpf_lxc.c:1471` | 同组跳过 VXLAN 封装 | 全部封装 |
| SNAT skip | `nat.h:785-791` | 同组跳过 masquerade | 全部 masquerade |
| 路由选择 | Linux 路由表 | 同组走直连路由 | 直连路由已安装但 BPF 先拦截走 tunnel |

**结果**：hybrid routing 实际等同 tunnel routing。同组 Pod 间流量被 VXLAN 封装 + BPF masquerade，吞吐量低。

### 1.3 根因

`cilium_subnet_map` 只包含节点 underlay CIDR（如 `172.30.130.0/24`），不含 Pod CIDR（如 `10.244.x.0/24`）。Pod IP 在 LPM trie 中查不到，返回 identity=0。

在 cluster-pool IPAM 下，Pod CIDR 从共享池分配，用户无法在 subnetTopology 中可靠地编码 Pod CIDR → underlay 映射。

## 2. 设计目标

- subnetTopology 仅描述节点 underlay 拓扑，用户不需编码 Pod CIDR
- Pod CIDR 分配保持自动，对用户不可见
- Go 路由安装和 BPF 行为使用同一拓扑决策源
- BPF 数据面不依赖 per-packet subnet LPM lookup
- 同组 Pod 流量：跳过 VXLAN/Geneve 封装 + 跳过 BPF masquerade/SNAT
- 跨组 Pod 流量：继续走 overlay tunnel
- 拓扑/节点变化安全收敛，优先 fallback 到 tunnel 而非产生 native-routing 黑洞

## 3. 核心架构

```
subnetTopology (underlay CIDRs)
        |
        v
  Go Topology Resolver (shared)
        |                        |
        v                        v
  路由安装决策              IPCache SkipTunnel flag
  (direct vs tunnel)        (same-group → true)
                                 |
                                 v
                    cilium_ipcache_v2
                    remote_endpoint_info.flag_skip_tunnel
                                 |
                                 v
                    BPF 消费 flag:
                    - skip VXLAN encapsulation
                    - skip BPF SNAT/masquerade
```

**关键语义**：`flag_skip_tunnel=true` 意味着"目的 prefix 属于与本节点同组的远程节点，流量可走 native routing，不需要封装也不需要 masquerade"。

**单源决策**：Resolver 是路由安装和 IPCache flag 的共同决策源，避免两者分歧。

## 4. 已有基础设施验证

以下基础设施全部已存在于当前代码中，无需新建：

| 组件 | 位置 | 状态 |
|------|------|------|
| `EndpointFlags` struct | `pkg/ipcache/types/types.go:110-127` | 含 `isInit` sentinel、`SetSkipTunnel()`、`Uint8()` |
| BPF `flag_skip_tunnel` bitfield | `bpf/lib/eps.h:100` | `__u8 flag_skip_tunnel:1` |
| `RemoteEndpointInfo.Flags` | `pkg/maps/ipcache/ipcache.go:160` | `align:"flag_skip_tunnel"` |
| IPCache metadata flattening | `pkg/ipcache/types.go:377-391` | 已处理 EndpointFlags，只合并 `IsValid()` 的 flags |
| BPF `flag_skip_tunnel` 消费 | bpf_host.c、bpf_lxc.c、nodeport.h、nat.h | 多处已有 check |
| IPCache → BPF 同步管道 | `OnIPIdentityCacheChange` → `BPFListener` → `cilium_ipcache_v2` | 已运行 |

**特别发现**：`nat.h:793` 和 `nat.h:1797` 已存在 `if (remote_ep->flag_skip_tunnel) return NAT_PUNT_TO_STACK;`，不带 `CONFIG(hybrid_routing_enabled)` guard。这意味着只要 PodCIDR ipcache 条目设了 `flag_skip_tunnel=true`，SNAT skip 就自动生效。

## 5. 实现方案

### 5.1 Topology Resolver

新建 `pkg/subnet/resolver.go`，作为共享拓扑决策组件：

```go
type Resolver interface {
    LookupGroupID(addr netip.Addr) uint32
    LocalGroupID() uint32
    NodeGroupID(node *nodeTypes.Node) uint32
    SameGroup(node *nodeTypes.Node) bool
    RequiresTunnelRoute(node *nodeTypes.Node) bool
}
```

规则：
- Group ID 0 = 未知/未匹配 → tunnel
- 同组非零 ID → native routing
- 不同组 / 未知 local group / 未知 remote group → tunnel
- 重叠 CIDR 用最长前缀匹配（LPM）

Resolver 作为 hive cell component，直接读 statedb subnet table（不缓存），每次调用返回最新数据。依赖：
- `statedb.Table[SubnetTableEntry]`（已有 LPM index）
- `node.LocalNodeStore`（获取本节点 IP）

Resolver 在 `pkg/subnet/cell.go` 中注册，同时注入到：
- `pkg/datapath/linux/node.go`（路由安装）
- `pkg/node/manager/manager.go`（IPCache flag 生成）

### 5.2 替换 node.go 中的内联拓扑逻辑

**当前**：`pkg/datapath/linux/node.go` 内联实现了 `lookupSubnetID()` 和 `nodeRequiresTunnelRoute()`，直接读 statedb。

**改为**：注入 Resolver，删除内联实现：

```go
// node.go - 删除 lookupSubnetID 方法，改用注入的 Resolver
func (n *linuxNodeHandler) nodeRequiresTunnelRoute(remoteNode *nodeTypes.Node) bool {
    if n.subnetResolver == nil {
        return true  // fallback: 无 resolver → 全部 tunnel
    }
    return n.subnetResolver.RequiresTunnelRoute(remoteNode)
}
```

`enableEncapsulation` 回调也改用 Resolver：

```go
n.enableEncapsulation = func(node *nodeTypes.Node) bool {
    if n.hybridMode() {
        return n.subnetResolver.RequiresTunnelRoute(node)
    }
    return n.nodeConfig.EnableEncapsulation
}
```

### 5.3 扩展 podCIDREntries 加入 EndpointFlags

**当前** (`pkg/node/manager/manager.go:932-955`)：

```go
func (m *manager) podCIDREntries(source, resource, prefixes, tunnelIP, encryptKey) {
    metadata := []ipcache.IPMetadata{
        worldLabelForPrefix(prefix.AsPrefix()),
        ipcacheTypes.TunnelPeer{Addr: tunnelIP},
        ipcacheTypes.EncryptKey(encryptKey),
        // ← 没有 EndpointFlags
    }
}
```

**改为**：新增 `skipTunnel bool` 参数：

```go
func (m *manager) podCIDREntries(
    source source.Source,
    resource ipcacheTypes.ResourceID,
    prefixes iter.Seq[cmtypes.PrefixCluster],
    tunnelIP netip.Addr,
    encryptKey uint8,
    skipTunnel bool,  // ← 新增
) iter.Seq[ipcache.MU] {
    return func(yield func(ipcache.MU) bool) {
        for prefix := range prefixes {
            if !prefix.IsValid() {
                continue
            }
            flags := ipcacheTypes.EndpointFlags{}
            flags.SetSkipTunnel(skipTunnel)  // ← 必须显式调用，isInit=true

            metadata := []ipcache.IPMetadata{
                worldLabelForPrefix(prefix.AsPrefix()),
                ipcacheTypes.TunnelPeer{Addr: tunnelIP},
                ipcacheTypes.EncryptKey(encryptKey),
                flags,
            }
            ...
        }
    }
}
```

**关键**：必须调用 `SetSkipTunnel(false)` 而不是传零值 `EndpointFlags{}`。零值 `isInit=false` 不会在 metadata flattening 中覆盖之前的 `true` 值（`pkg/ipcache/types.go:377`：`if info.endpointFlags.IsValid()`）。

### 5.4 计算 skipTunnel per remote node

在 NodeUpdated 调用 podCIDREntries 的位置（`manager.go:788-801`）：

```go
if !n.IsLocal() {
    // 计算 skipTunnel
    skipTunnel := false
    if m.conf.RoutingMode == option.RoutingModeHybrid && m.subnetResolver != nil {
        skipTunnel = m.subnetResolver.SameGroup(&n)
    }

    ipv4PodCIDRs := n.GetIPv4AllocCIDRs()
    ipv6PodCIDRs := n.GetIPv6AllocCIDRs()
    mu := make([]ipcache.MU, 0, len(ipv4PodCIDRs)+len(ipv6PodCIDRs))
    for entry := range m.podCIDREntries(n.Source, resource,
        m.cidrsToPrefixesCluster(&n, ipv4PodCIDRs...), nodeIP, n.EncryptionKey, skipTunnel) {
        mu = append(mu, entry)
        podCIDRsAdded = append(podCIDRsAdded, entry.Prefix.AsPrefix())
    }
    for entry := range m.podCIDREntries(n.Source, resource,
        m.cidrsToPrefixesCluster(&n, ipv6PodCIDRs...), nodeIP, n.EncryptionKey, skipTunnel) {
        mu = append(mu, entry)
        podCIDRsAdded = append(podCIDRsAdded, entry.Prefix.AsPrefix())
    }
    m.ipcache.UpsertMetadataBatch(mu...)
}
```

### 5.5 Node IP 地址也设 SkipTunnel

Node 的 host/health/ingress IP 条目也需要 SkipTunnel flag。当前 `manager.go:762-766` 已有 EndpointFlags 但只设 RemoteCluster：

```go
// 当前 (manager.go:729-766)
endpointFlags := ipcacheTypes.EndpointFlags{}
if n.Cluster != m.conf.ClusterName {
    endpointFlags.SetRemoteCluster(true)
}
// 不设 SkipTunnel
```

**改为**：

```go
endpointFlags := ipcacheTypes.EndpointFlags{}
if n.Cluster != m.conf.ClusterName {
    endpointFlags.SetRemoteCluster(true)
}
// Hybrid mode: set SkipTunnel for same-group node IPs
if m.conf.RoutingMode == option.RoutingModeHybrid && m.subnetResolver != nil {
    endpointFlags.SetSkipTunnel(m.subnetResolver.SameGroup(&n))
} else if !n.IsLocal() && m.nodeAddressHasTunnelIP(address) {
    // Native routing mode: existing behavior
    endpointFlags.SetSkipTunnel(true)
}
```

### 5.6 removeNodeFromIPCache 需要同步更新

`removeNodeFromIPCache`（`manager.go:932-1045`）也需要传 SkipTunnel flag 以正确清除旧条目。删除时传 `skipTunnel=false` 以确保 flag 被显式重置：

```go
for entry := range m.podCIDREntries(oldNode.Source, resource,
    m.cidrsToPrefixesCluster(&oldNode, oldIPv4PodCIDRs...), oldNodeIP, oldNode.EncryptionKey, false) {
    ...
}
```

## 6. BPF 侧改动

### 6.1 短期（兼容性优先）

保留 `CONFIG(hybrid_routing_enabled)` 和 `same_subnet_id` 作为冗余路径：

```c
// bpf_host.c, bpf_lxc.c
skip_tunnel = (info && info->flag_skip_tunnel) || same_subnet_id;

// nat.h SNAT skip
if (CONFIG(hybrid_routing_enabled)) {
    __u32 src_subnet_id = lookup_ip4_subnet_id(tuple->saddr);
    __u32 dst_subnet_id = lookup_ip4_subnet_id(tuple->daddr);
    if ((src_subnet_id == dst_subnet_id) && (src_subnet_id != 0))
        return NAT_PUNT_TO_STACK;
}
if (remote_ep->flag_skip_tunnel)
    return NAT_PUNT_TO_STACK;
```

这样即使 Go 侧 IPCache flag 有 bug，BPF 仍有 subnet map 作为 fallback。**但注意**：当前 subnet map 的 Pod IP 查找也是失败的，所以这个 fallback 实际不可用。短期方案的价值在于避免 BPF 编译变化引入新风险。

### 6.2 长期（最终架构）

移除 per-packet subnet LPM lookup，完全依赖 IPCache flag：

**bpf_host.c / bpf_lxc.c** — 删除 `same_subnet_id` 计算：
```c
// 删除:
// bool same_subnet_id = false;
// if (CONFIG(hybrid_routing_enabled)) { ... same_subnet_id = ... }
// skip_tunnel = (info && info->flag_skip_tunnel) || same_subnet_id;

// 改为:
skip_tunnel = (info && info->flag_skip_tunnel);
```

**nat.h** — 删除 subnet lookup，只保留 `flag_skip_tunnel`：
```c
// 删除:
// if (CONFIG(hybrid_routing_enabled)) { ... subnet lookup ... }

// 已有的 check 足够:
if (remote_ep->flag_skip_tunnel)
    return NAT_PUNT_TO_STACK;
```

**subnet.h** — 删除 `DECLARE_CONFIG(hybrid_routing_enabled)` 和 `cilium_subnet_map`。

> 注意：`CONFIG(hybrid_routing_enabled)` 在最终设计中仍然有保留价值。
> 在 native routing 模式下 `flag_skip_tunnel=true` 对所有远端生效，
> SNAT 代码在 `TUNNEL_MODE` 未定义时不触发，所以不带 guard 的
> `flag_skip_tunnel` check 在 native 模式下是安全冗余。
> 但如需区分 hybrid 专属逻辑（如未来新增的 per-packet 行为差异），
> 应保留此 flag。建议保留，不删。

## 7. 事件处理

### 7.1 节点 Add/Update

触发条件：节点创建、underlay IP 变化、PodCIDR 变化、加密 key 变化

动作序列：
1. 用 Resolver 计算远程节点 group → skipTunnel
2. 更新该节点的路由（direct 或 tunnel）
3. Upsert 远程 PodCIDR IPCache metadata，带 `EndpointFlags{SetSkipTunnel(skipTunnel)}`
4. Upsert 节点 host IP IPCache metadata，带 `EndpointFlags`
5. 如果 PodCIDR 变了，删除旧 PodCIDR 的 stale metadata

### 7.2 节点 Delete

1. 删除该节点的所有路由
2. 删除该节点的所有 IPCache 条目（PodCIDR + host IP），用相同 metadata shape 确保正确清除

### 7.3 subnetTopology 变化

全局拓扑变更，必须刷新路由 + IPCache flags。

**安全序列**（保守收敛，避免 native routing 黑洞）：

```
1. 解析验证新 topology
2. 更新 Resolver 状态（statedb subnet table 全量重写）
3. 对所有远程 PodCIDR 和节点 IP：Upsert with SkipTunnel=false
   → BPF 立刻全部走 tunnel（安全降级）
4. 重新计算所有远程节点的路由
   → 先装 direct route 再装 tunnel route（先装 route 再设 flag）
5. 对同组远程节点：Upsert with SkipTunnel=true
   → 此时 direct route 已在位，BPF 开始跳 tunnel
```

这个顺序的失败模式是安全的：过渡期间流量可能短暂走 tunnel（性能降级但不断连），BPF 不会在没有 direct route 时跳 tunnel（不会产生黑洞）。

### 7.4 并发与一致性

拓扑变化和节点更新可能并发。实现应确保：
- 路由 reconciliation 和 IPCache flag reconciliation 使用同一 Resolver 快照
- stale PodCIDR 条目被清除
- 节点从同组变为跨组时，`SkipTunnel=false` 必须显式写入（不能传零值 `EndpointFlags{}`）
- 数据面永远不依赖用户维护的 PodCIDR topology

不需要完全事务性协调；保守的 reconciliation 顺序（clear_flags → reconcile_routes → set_allowed_flags）已足够防止黑洞。

## 8. 需修改的文件清单

### Go 侧

| 文件 | 改动 |
|------|------|
| `pkg/subnet/resolver.go` | **新建**。Resolver interface + 实现，读 statedb subnet table + LocalNodeStore |
| `pkg/subnet/cell.go` | 注册 Resolver，注入到 node handler 和 node manager |
| `pkg/datapath/linux/node.go` | 删除 `lookupSubnetID()`，改用注入的 Resolver；`nodeRequiresTunnelRoute()` 和 `enableEncapsulation` 回调改用 Resolver |
| `pkg/datapath/linux/cell.go` | 注入 Resolver 到 linuxNodeHandler |
| `pkg/node/manager/manager.go` | `podCIDREntries` 新增 `skipTunnel bool` 参数；NodeUpdated 计算 skipTunnel；nodeAddressHasTunnelIP 处设 SkipTunnel；removeNodeFromIPCache 同步更新 |
| `pkg/node/manager/cell.go` | 注入 Resolver 到 manager |
| `pkg/subnet/watcher.go` | topology 变化时触发全量节点 IPCache 刷新（调用 node manager 或触发 AllNodeValidateImplementation） |

### BPF 侧（短期不改，长期改动）

| 文件 | 短期 | 长期 |
|------|------|------|
| `bpf/bpf_host.c` | 不改 | 删除 same_subnet_id 计算，只用 flag_skip_tunnel |
| `bpf/bpf_lxc.c` | 不改 | 同上 |
| `bpf/lib/nat.h` | 不改 | 删除 subnet lookup，只保留 flag_skip_tunnel check |
| `bpf/lib/subnet.h` | 不改 | 删除 DECLARE_CONFIG(hybrid_routing_enabled) 和 cilium_subnet_map |
| `bpf/lib/eps.h` | 不改 | 不改（flag_skip_tunnel 已存在） |

### Helm / 配置

| 文件 | 改动 |
|------|------|
| 不改 | subnetTopology 格式保持不变（underlay CIDR only） |
| 不改 | 用户配置不变：`routingMode: hybrid` + `subnetTopology: "172.30.130.0/24;172.18.0.0/20"` |

## 9. cilium_subnet_map 处理

### 短期：保留但降级

`cilium_subnet_map` 和 statedb subnet table 继续存在。BPF 侧的 subnet lookup 实际无效（Pod IP 不匹配），但保留作为安全冗余，避免同时改 BPF + Go 引入风险。

Go 侧 Resolver 读 statedb table（不读 BPF map），路由安装逻辑不变。

### 长期：移除 BPF map

当 IPCache SkipTunnel flag 完全验证稳定后：
1. BPF 代码移除 subnet lookup 和 `same_subnet_id`
2. 移除 `cilium_subnet_map` BPF map 定义
3. 移除 subnet reconciler（不再需要同步 statedb → BPF map）
4. statedb subnet table 保留（Resolver 仍需要）
5. `pkg/maps/subnet/` 中的 BPF map 相关代码可简化或移除

## 10. 验证计划

### 10.1 功能验证

部署后执行以下命令确认正确性：

**检查 IPCache flag**：
```bash
cilium-dbg bpf ipcache get <remote-pod-ip>
# 期望输出: tunnelendpoint=<remote-node-ip> flags=skiptunnel
```

**检查同组流量不走 VXLAN**：
```bash
# 在同组节点间跑 iperf
iperf3 -c <same-group-pod-ip>

# 同时观察 VXLAN 接口计数器
ip -s link show cilium_vxlan
# 期望: VXLAN counters 不显著增长
```

**检查跨组流量走 VXLAN**：
```bash
iperf3 -c <cross-group-pod-ip>
ip -s link show cilium_vxlan
# 期望: VXLAN counters 显著增长
```

**检查路由表**：
```bash
ip route get <same-group-node-ip>
# 期望: 直接走物理网卡，不走 tunnel

ip route get <cross-group-node-ip>
# 期望: 走 cilium_host/tunnel
```

**检查 BPF config**：
```bash
cilium-dbg bpf config list
# hybrid_routing_enabled 不在这里（它不是 cilium_config_map 的字段）
# 它是 BPF 程序的 .rodata.config section，由 agent 在加载时设定
```

### 10.2 拓扑变化验证

修改 subnetTopology（如从一个组拆为两个组），确认：
- 过渡期间流量不中断
- 旧组节点间 Pod 流量降级到 tunnel（安全）
- 新路由安装后，同组流量恢复 native routing
- IPCache flag 正确更新

### 10.3 节点增删验证

添加新节点到同组：
- 该节点 PodCIDR IPCache 条目带 `flag_skip_tunnel=true`
- Direct route 自动安装
- Pod 间 iperf 吞吐正常

删除节点：
- 该节点 PodCIDR IPCache 条目被清除
- 路由被删除
- 不残留 stale flag

## 11. 与当前部署的关系

当前部署的 v1 版本（含 subnet map LPM fix）已上线。此方案是 v2 修复：

- v1 的 subnet map + statedb table + watcher 代码**保留**
- v2 新增 Resolver + IPCache SkipTunnel flag
- v2 短期不改 BPF 代码，只改 Go 侧
- v2 的 IPCache SkipTunnel 是**新增的冗余路径**，与 v1 的 subnet map 同时存在
- IPCache SkipTunnel 生效后，BPF 的 subnet fallback 查找实际无意义（Pod IP 匹配不到），但保留不删以防万一
- 长期清理时统一移除 subnet BPF map 和 BPF 侧 subnet lookup

**v2 部署步骤**：
1. 重新编译 cilium-agent 镜像（含 Go 侧改动）
2. 重新打包 Helm chart（无需改 chart，Go 侧自动处理）
3. 滚动更新部署到集群
4. 验证 IPCache flag 正确设置
5. 验证同组流量走 native routing
6. 验证跨组流量走 tunnel