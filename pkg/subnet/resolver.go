// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"context"
	"net/netip"
	"time"

	"github.com/cilium/statedb"

	subnetTable "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// LocalNodeGetter abstracts fetching the local node IP for group determination.
// *node.LocalNodeStore satisfies this interface.
type LocalNodeGetter interface {
	Get(ctx context.Context) (node.LocalNode, error)
}

// Resolver determines whether two nodes belong to the same subnet topology group.
// It is the single source of truth for both route installation decisions and
// IPCache flag_skip_tunnel generation.
type Resolver interface {
	// LookupGroupID returns the topology group ID for the given IP address
	// using longest-prefix-match against the subnet topology table.
	// Returns 0 if no matching prefix is found.
	LookupGroupID(addr netip.Addr) uint32

	// LocalGroupID returns the topology group ID of the local node.
	// Returns 0 if the local node's IP is not found in any topology group.
	LocalGroupID() uint32

	// NodeGroupID returns the topology group ID for the given remote node,
	// using its primary node IP (IPv4 first, then IPv6).
	// Returns 0 if the node's IP is not found in any topology group.
	NodeGroupID(node *nodeTypes.Node) uint32

	// SameGroup returns true if the given remote node is in the same
	// topology group as the local node. Both must have non-zero group IDs
	// that equal.
	SameGroup(node *nodeTypes.Node) bool

	// RequiresTunnelRoute returns true if the remote node requires tunnel
	// encapsulation — i.e., it is not in the same group as the local node,
	// or either node's group is unknown (0).
	RequiresTunnelRoute(node *nodeTypes.Node) bool
}

type resolverImpl struct {
	db          *statedb.DB
	subnetTable statedb.Table[subnetTable.SubnetTableEntry]
	localNode   LocalNodeGetter
}

// NewResolver creates a Resolver that reads the subnet topology from statedb
// and uses LocalNodeGetter to determine the local node's group.
func NewResolver(db *statedb.DB, subnetTable statedb.Table[subnetTable.SubnetTableEntry], localNode LocalNodeGetter) Resolver {
	return &resolverImpl{
		db:          db,
		subnetTable: subnetTable,
		localNode:   localNode,
	}
}

func (r *resolverImpl) LookupGroupID(addr netip.Addr) uint32 {
	txn := r.db.ReadTxn()
	entry, _, found := r.subnetTable.Get(txn, subnetTable.SubnetLPMIndex.Query(addr))
	if found {
		return entry.Value
	}
	return 0
}

func (r *resolverImpl) LocalGroupID() uint32 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := r.localNode.Get(ctx)
	if err != nil {
		return 0
	}
	// LocalNode embeds nodeTypes.Node, so GetNodeIP is available.
	localIP := ln.GetNodeIP(false)
	if localIP == nil {
		localIP = ln.GetNodeIP(true)
	}
	if localIP == nil {
		return 0
	}
	// Normalize IPv4: net.IP from GetNodeIP may be 16-byte (IPv4-mapped IPv6),
	// which netip.AddrFromSlice interprets as IPv6. Use To4() to get 4-byte form.
	if v4 := localIP.To4(); v4 != nil {
		localIP = v4
	}
	localAddr, ok := netip.AddrFromSlice(localIP)
	if !ok {
		return 0
	}
	return r.LookupGroupID(localAddr)
}

func (r *resolverImpl) NodeGroupID(n *nodeTypes.Node) uint32 {
	if n == nil {
		return 0
	}
	remoteIP := n.GetNodeIP(false)
	if remoteIP == nil {
		remoteIP = n.GetNodeIP(true)
	}
	if remoteIP == nil {
		return 0
	}
	if v4 := remoteIP.To4(); v4 != nil {
		remoteIP = v4
	}
	remoteAddr, ok := netip.AddrFromSlice(remoteIP)
	if !ok {
		return 0
	}
	return r.LookupGroupID(remoteAddr)
}

func (r *resolverImpl) SameGroup(n *nodeTypes.Node) bool {
	localGroup := r.LocalGroupID()
	remoteGroup := r.NodeGroupID(n)
	return localGroup != 0 && remoteGroup != 0 && localGroup == remoteGroup
}

func (r *resolverImpl) RequiresTunnelRoute(n *nodeTypes.Node) bool {
	return !r.SameGroup(n)
}