// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/datapath/config"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func TestHybridMode(t *testing.T) {
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})

	tests := []struct {
		name               string
		enableEncap        bool
		requiresNative     bool
		expectedHybridMode bool
	}{
		{
			name:               "tunnel mode only",
			enableEncap:        true,
			requiresNative:     false,
			expectedHybridMode: false,
		},
		{
			name:               "native mode only",
			enableEncap:        false,
			requiresNative:     true,
			expectedHybridMode: false,
		},
		{
			name:               "hybrid mode",
			enableEncap:        true,
			requiresNative:     true,
			expectedHybridMode: true,
		},
		{
			name:               "neither enabled",
			enableEncap:        false,
			requiresNative:     false,
			expectedHybridMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nh := newNodeHandler(log, DatapathConfiguration{HostDevice: "test"}, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, nil)
			nh.NodeConfigurationChanged(config.Config{
				EnableEncapsulation:   tt.enableEncap,
				RequiresNativeRouting: tt.requiresNative,
			})
			assert.Equal(t, tt.expectedHybridMode, nh.hybridMode())
		})
	}
}

func TestNodeRequiresTunnelRouteNil(t *testing.T) {
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nh := newNodeHandler(log, DatapathConfiguration{HostDevice: "test"}, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, nil)
	nh.NodeConfigurationChanged(config.Config{
		EnableEncapsulation:   true,
		RequiresNativeRouting: true,
	})

	// nil remote node should always require tunnel
	assert.True(t, nh.nodeRequiresTunnelRoute(nil))
}

func TestNodeRequiresTunnelRouteNoIP(t *testing.T) {
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			Name: "local",
		},
	})
	nh := newNodeHandler(log, DatapathConfiguration{HostDevice: "test"}, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, nil)
	nh.NodeConfigurationChanged(config.Config{
		EnableEncapsulation:   true,
		RequiresNativeRouting: true,
	})

	// remote node with no IP should require tunnel
	remoteNoIP := &nodeTypes.Node{Name: "remote"}
	assert.True(t, nh.nodeRequiresTunnelRoute(remoteNoIP))
}

func TestNodeRequiresTunnelRouteNoDB(t *testing.T) {
	log := hivetest.Logger(t)
	lns := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			Name:        "local",
			IPAddresses: []nodeTypes.Address{
				{IP: net.ParseIP("10.0.0.1"), Type: addressing.NodeInternalIP},
			},
		},
	})
	nh := newNodeHandler(log, DatapathConfiguration{HostDevice: "test"}, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, nil)
	nh.NodeConfigurationChanged(config.Config{
		EnableEncapsulation:   true,
		RequiresNativeRouting: true,
	})

	// Without subnet DB, all IPs return group 0, so tunnel is always required
	remoteSameIP := &nodeTypes.Node{
		Name: "remote",
		IPAddresses: []nodeTypes.Address{
			{IP: net.ParseIP("10.0.0.5"), Type: addressing.NodeInternalIP},
		},
	}
	assert.True(t, nh.nodeRequiresTunnelRoute(remoteSameIP))
}