// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubnetTableCreation(t *testing.T) {
	db := statedb.New()
	tbl, err := NewSubnetEntryTable(db)
	require.NoError(t, err, "Creating subnet table should not panic")

	wTx := db.WriteTxn(tbl)

	// Insert entries covering overlapping CIDRs across groups
	entries := []SubnetTableEntry{
		NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/8"), 1),  // group 1 (broad)
		NewSubnetEntry(netip.MustParsePrefix("10.20.0.0/24"), 2), // group 2 (specific, overlaps with group 1)
		NewSubnetEntry(netip.MustParsePrefix("172.30.130.0/24"), 1),
		NewSubnetEntry(netip.MustParsePrefix("172.18.0.0/20"), 2),
	}
	for _, e := range entries {
		_, _, err := tbl.Insert(wTx, e)
		require.NoError(t, err, "Inserting subnet entry should succeed")
	}
	wTx.Commit()

	rTx := db.ReadTxn()

	// Verify primary index (string) lookup works
	entry, _, found := tbl.Get(rTx, SubnetPrefixIndex.Query("10.0.0.0/8"))
	require.True(t, found, "Should find entry by primary index")
	assert.Equal(t, uint32(1), entry.Value)

	entry, _, found = tbl.Get(rTx, SubnetPrefixIndex.Query("10.20.0.0/24"))
	require.True(t, found)
	assert.Equal(t, uint32(2), entry.Value)

	// Verify LPM secondary index returns longest prefix match
	// 10.20.0.5 falls within both 10.0.0.0/8 (group 1) and 10.20.0.0/24 (group 2)
	// LPM should return the more specific match: 10.20.0.0/24 (group 2)
	entry, _, found = tbl.Get(rTx, SubnetLPMIndex.Query(netip.MustParseAddr("10.20.0.5")))
	require.True(t, found, "LPM query should find a match")
	assert.Equal(t, netip.MustParsePrefix("10.20.0.0/24"), entry.Key, "LPM should return most specific prefix")
	assert.Equal(t, uint32(2), entry.Value, "LPM should return group 2 for overlapping CIDR")

	// 10.5.0.5 only falls within 10.0.0.0/8 (group 1), no more specific match
	entry, _, found = tbl.Get(rTx, SubnetLPMIndex.Query(netip.MustParseAddr("10.5.0.5")))
	require.True(t, found)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), entry.Key)
	assert.Equal(t, uint32(1), entry.Value)

	// 172.30.130.10 falls within 172.30.130.0/24 (group 1)
	entry, _, found = tbl.Get(rTx, SubnetLPMIndex.Query(netip.MustParseAddr("172.30.130.10")))
	require.True(t, found)
	assert.Equal(t, uint32(1), entry.Value)

	// 172.18.5.10 falls within 172.18.0.0/20 (group 2)
	entry, _, found = tbl.Get(rTx, SubnetLPMIndex.Query(netip.MustParseAddr("172.18.5.10")))
	require.True(t, found)
	assert.Equal(t, uint32(2), entry.Value)

	// 192.168.1.1 falls within none of the entries
	_, _, found = tbl.Get(rTx, SubnetLPMIndex.Query(netip.MustParseAddr("192.168.1.1")))
	assert.False(t, found, "LPM should not find match for IP outside all subnets")
}

func TestSubnetTableDeleteAll(t *testing.T) {
	db := statedb.New()
	tbl, err := NewSubnetEntryTable(db)
	require.NoError(t, err)

	wTx := db.WriteTxn(tbl)
	_, _, err = tbl.Insert(wTx, NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/8"), 1))
	require.NoError(t, err)
	wTx.Commit()

	// DeleteAll should work without panic (this was the operation that triggered the LPM panic)
	wTx = db.WriteTxn(tbl)
	err = tbl.DeleteAll(wTx)
	require.NoError(t, err, "DeleteAll should not panic")
	wTx.Commit()

	rTx := db.ReadTxn()
	_, _, found := tbl.Get(rTx, SubnetPrefixIndex.Query("10.0.0.0/8"))
	assert.False(t, found, "Entry should be deleted after DeleteAll")
}