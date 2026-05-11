// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	subnetTable "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// mockLocalNodeGetter implements LocalNodeGetter for testing.
type mockLocalNodeGetter struct {
	localNode node.LocalNode
}

func (m *mockLocalNodeGetter) Get(_ context.Context) (node.LocalNode, error) {
	return m.localNode, nil
}

func makeLocalNode(ip string) node.LocalNode {
	ln := node.LocalNode{}
	ln.Node = nodeTypes.Node{
		IPAddresses: []nodeTypes.Address{
			{IP: netip.MustParseAddr(ip).AsSlice(), Type: "InternalIP"},
		},
	}
	return ln
}

func makeRemoteNode(ip string) *nodeTypes.Node {
	n := &nodeTypes.Node{}
	n.IPAddresses = []nodeTypes.Address{
		{IP: netip.MustParseAddr(ip).AsSlice(), Type: "InternalIP"},
	}
	return n
}

func setupResolverTest(t *testing.T, entries []subnetTable.SubnetTableEntry, localIP string) Resolver {
	db := statedb.New()
	tbl, err := subnetTable.NewSubnetEntryTable(db)
	require.NoError(t, err)

	wTx := db.WriteTxn(tbl)
	for _, e := range entries {
		_, _, err := tbl.Insert(wTx, e)
		require.NoError(t, err)
	}
	wTx.Commit()

	localGetter := &mockLocalNodeGetter{localNode: makeLocalNode(localIP)}
	return NewResolver(db, tbl, localGetter)
}

func TestResolverLookupGroupID(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/8"), 1),
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.20.0.0/24"), 2),
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
	}

	r := setupResolverTest(t, entries, "10.0.0.1")

	// Broad prefix match
	assert.Equal(t, uint32(1), r.LookupGroupID(netip.MustParseAddr("10.5.0.1")))
	// More specific prefix match (LPM)
	assert.Equal(t, uint32(2), r.LookupGroupID(netip.MustParseAddr("10.20.0.5")))
	// No match
	assert.Equal(t, uint32(0), r.LookupGroupID(netip.MustParseAddr("192.168.1.1")))
	// Exact group match
	assert.Equal(t, uint32(1), r.LookupGroupID(netip.MustParseAddr("172.30.130.10")))
}

func TestResolverLocalGroupID(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.18.0.0/20"), 2),
	}

	// Local node in group 1
	r := setupResolverTest(t, entries, "172.30.130.5")
	assert.Equal(t, uint32(1), r.LocalGroupID())

	// Local node in group 2
	r2 := setupResolverTest(t, entries, "172.18.5.1")
	assert.Equal(t, uint32(2), r2.LocalGroupID())

	// Local node not in any group
	r3 := setupResolverTest(t, entries, "192.168.1.1")
	assert.Equal(t, uint32(0), r3.LocalGroupID())
}

func TestResolverNodeGroupID(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.18.0.0/20"), 2),
	}

	r := setupResolverTest(t, entries, "172.30.130.5")

	assert.Equal(t, uint32(1), r.NodeGroupID(makeRemoteNode("172.30.130.10")))
	assert.Equal(t, uint32(2), r.NodeGroupID(makeRemoteNode("172.18.5.1")))
	assert.Equal(t, uint32(0), r.NodeGroupID(makeRemoteNode("192.168.1.1")))
	assert.Equal(t, uint32(0), r.NodeGroupID(nil))
}

func TestResolverSameGroup(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.18.0.0/20"), 2),
	}

	r := setupResolverTest(t, entries, "172.30.130.5")

	// Same group
	assert.True(t, r.SameGroup(makeRemoteNode("172.30.130.10")))
	// Different group
	assert.False(t, r.SameGroup(makeRemoteNode("172.18.5.1")))
	// Remote node not in any group
	assert.False(t, r.SameGroup(makeRemoteNode("192.168.1.1")))
}

func TestResolverRequiresTunnelRoute(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.18.0.0/20"), 2),
	}

	r := setupResolverTest(t, entries, "172.30.130.5")

	// Same group → no tunnel required
	assert.False(t, r.RequiresTunnelRoute(makeRemoteNode("172.30.130.10")))
	// Different group → tunnel required
	assert.True(t, r.RequiresTunnelRoute(makeRemoteNode("172.18.5.1")))
	// Unknown remote → tunnel required
	assert.True(t, r.RequiresTunnelRoute(makeRemoteNode("192.168.1.1")))
}

func TestResolverLocalGroupUnknownRequiresTunnel(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
	}

	// Local node not in any group → all remote nodes require tunnel
	r := setupResolverTest(t, entries, "192.168.1.1")
	assert.True(t, r.RequiresTunnelRoute(makeRemoteNode("172.30.130.10")))
}

func TestResolverOverlappingCIDRs(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/8"), 1),   // broad
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.20.0.0/24"), 2),  // specific
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.20.1.0/24"), 1),  // another specific in group 1
	}

	r := setupResolverTest(t, entries, "10.20.1.5")

	// 10.5.0.1 matches /8 only → group 1, local is group 1 → same group
	assert.True(t, r.SameGroup(makeRemoteNode("10.5.0.1")))
	// 10.20.0.5 matches /24 → group 2, local is group 1 → different group
	assert.False(t, r.SameGroup(makeRemoteNode("10.20.0.5")))
}

// TestResolverIPv4MappedIPv6Normalization verifies that the To4() normalization
// correctly handles 16-byte IPv4-mapped IPv6 addresses (as returned by net.ParseIP).
// Without normalization, netip.AddrFromSlice would interpret these as IPv6 addresses.
func TestResolverIPv4MappedIPv6Normalization(t *testing.T) {
	entries := []subnetTable.SubnetTableEntry{
		subnetTable.NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
	}

	db := statedb.New()
	tbl, err := subnetTable.NewSubnetEntryTable(db)
	require.NoError(t, err)

	wTx := db.WriteTxn(tbl)
	_, _, err = tbl.Insert(wTx, entries[0])
	require.NoError(t, err)
	wTx.Commit()

	// Construct node with 16-byte IPv4-mapped IPv6 address (as net.ParseIP does)
	n := &nodeTypes.Node{
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("172.30.130.5"), Type: "InternalIP"}, // 16-byte ::ffff:172.30.130.5
		},
	}

	ln := node.LocalNode{}
	ln.Node = nodeTypes.Node{
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("172.30.130.5"), Type: "InternalIP"},
		},
	}

	localGetter := &mockLocalNodeGetter{localNode: ln}
	r := NewResolver(db, tbl, localGetter)

	// Both LocalGroupID and SameGroup should work correctly despite 16-byte addresses
	assert.Equal(t, uint32(1), r.LocalGroupID(), "LocalGroupID should match via To4() normalization")
	assert.True(t, r.SameGroup(n), "SameGroup should match via To4() normalization")
}