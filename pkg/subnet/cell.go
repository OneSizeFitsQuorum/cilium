// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	subnetTable "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the subnet watcher and resolver functionality
var Cell = cell.Module(
	"subnet",
	"Subnet watcher resolver and management",

	cell.Config(DefaultConfig),

	cell.Provide(
		newSubnetWatcher,
		newResolver,
	),

	cell.Invoke(
		registerSubnetWatcher,
	),
)

func newResolver(db *statedb.DB, subnetTable statedb.Table[subnetTable.SubnetTableEntry], localNodeStore *node.LocalNodeStore) Resolver {
	return NewResolver(db, subnetTable, localNodeStore)
}

func registerSubnetWatcher(cfg *option.DaemonConfig, fence regeneration.Fence, sw *SubnetWatcher) {
	if cfg.RoutingMode != option.RoutingModeHybrid {
		sw.logger.Debug("Routing mode is not hybrid, skipping subnet watcher")
		return
	}

	synced := make(chan struct{})

	// Add a fence to ensure that subnet map is ready before starting endpoint regeneration.
	fence.Add("subnet-map", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-synced:
			sw.logger.Info("Subnet topology dynamic config synced")
			return nil
		}
	})

	sw.jobGroup.Add(job.OneShot("subnet-watcher", func(ctx context.Context, health cell.Health) error {
		sw.logger.Info("Starting subnet topology dynamic config watcher")
		for {
			entry, found, w := dynamicconfig.WatchKey(sw.db.ReadTxn(), sw.dynamicConfigTable, SubnetTopologyConfigKey)
			if found {
				sw.logger.Info("Detected change in subnet-topology dynamic config")
				if err := sw.processSubnetConfigEntry(entry); err != nil {
					sw.logger.Error("Failed to process subnet-topology dynamic config", logfields.Error, err)
					health.Degraded("Failed to process subnet-topology dynamic config", err)
				} else {
					health.OK("subnet-topology dynamic config processed successfully")
				}
			} else {
				sw.logger.Info("Subnet-topology config key not found, clearing subnet entries")
				if err := sw.processSubnetConfigEntry(dynamicconfig.DynamicConfig{Key: dynamicconfig.Key{Name: SubnetTopologyConfigKey}, Value: ""}); err != nil {
					sw.logger.Error("Failed to clear subnet entries", logfields.Error, err)
					health.Degraded("Failed to clear subnet entries", err)
				} else {
					health.OK("subnet entries cleared successfully")
				}
			}

			// Signal initial sync is complete.
			select {
			case <-synced:
			default:
				close(synced)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-w:
				continue
			}
		}
	}))
}