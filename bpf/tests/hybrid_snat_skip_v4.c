// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Test Matrix for hybrid SNAT skip logic (IPv4):
 *
 * | Test Case              | src_subnet_id | dst_subnet_id | hybrid_enabled | remote_masq | Expected        |
 * |------------------------|---------------|---------------|----------------|-------------|-----------------|
 * | same_subnet_skip       | 100           | 100           | true           | false       | NAT_PUNT_TO_STACK|
 * | different_subnet       | 100           | 200           | true           | false       | NAT_NEEDED      |
 * | zero_subnet_boundary   | 0             | 0             | true           | false       | NAT_NEEDED      |
 * | remote_masq_override   | 100           | 100           | true           | true        | NAT_NEEDED      |
 *
 * Key behaviors:
 * - SNAT skipped when (src_subnet_id == dst_subnet_id && src_subnet_id != 0)
 * - enable_remote_node_masquerade=true overrides hybrid skip (user intent)
 * - Zero subnet_id excluded from skip (fallback to normal behavior)
 */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_SCTP
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define TUNNEL_MODE
#include <bpf/config/global.h>
#include <bpf/config/node.h>

#define DEBUG

#define ENABLE_BPF_MASQUERADE 1
#define ENABLE_MASQUERADE_IPV4 1
#define IS_BPF_HOST 1

#include <lib/dbg.h>
#include <lib/time.h>
#include "bpf_nat_tuples.h"

#define IPV4_MASQUERADE bpf_htonl(0x0A000001) /* 10.0.0.1 */
#define IPV4_SRC        bpf_htonl(0xC0A80101) /* 192.168.1.1 */
#define IPV4_DST        bpf_htonl(0xC0A80201) /* 192.168.2.1 */

#include <lib/conntrack.h>
#include <lib/nat.h>

#include "lib/ipcache.h"
#include "lib/subnet.h"

/* Test 1: Same subnet should skip SNAT */
ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = IPV4_MASQUERADE })
ASSIGN_CONFIG(bool, enable_remote_node_masquerade, false)
ASSIGN_CONFIG(bool, hybrid_routing_enabled, true)
ASSIGN_CONFIG(__u32, trace_payload_len, 128UL)
ASSIGN_CONFIG(bool, enable_extended_ip_protocols, false)

CHECK("tc", "hybrid_snat_v4_same_subnet_skip")
int test_hybrid_snat_v4_same_subnet_skip(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr ip4 = { .protocol = IPPROTO_TCP };
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	test_init();

	subnet_v4_add_entry(IPV4_SRC, 100);
	subnet_v4_add_entry(IPV4_DST, 100);
	ipcache_v4_add_entry(IPV4_DST, 0, REMOTE_NODE_ID, 0, 0);

	tuple.daddr = IPV4_DST;
	tuple.saddr = IPV4_SRC;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.sport = bpf_htons(12345);
	tuple.dport = bpf_htons(443);
	tuple.flags = NAT_DIR_EGRESS;

	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};

	ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
	assert(ret == NAT_PUNT_TO_STACK);
	assert(target.addr == 0);

	test_finish();
	return 0;
}

/* Test 2: Different subnet should NOT skip SNAT */
CHECK("tc", "hybrid_snat_v4_different_subnet")
int test_hybrid_snat_v4_different_subnet(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr ip4 = { .protocol = IPPROTO_TCP };
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	test_init();

	subnet_v4_add_entry(IPV4_SRC, 100);
	subnet_v4_add_entry(IPV4_DST, 200);
	ipcache_v4_add_entry(IPV4_DST, 0, REMOTE_NODE_ID, 0, 0);
	ipcache_v4_add_entry(IPV4_SRC, 0, LOCAL_NODE_ID, 0, 0);

	tuple.daddr = IPV4_DST;
	tuple.saddr = IPV4_SRC;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.sport = bpf_htons(12345);
	tuple.dport = bpf_htons(443);
	tuple.flags = NAT_DIR_EGRESS;

	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};

	ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
	assert(ret == NAT_NEEDED);
	assert(target.addr == IPV4_MASQUERADE);

	test_finish();
	return 0;
}

/* Test 3: Zero subnet_id should NOT skip SNAT */
CHECK("tc", "hybrid_snat_v4_zero_subnet")
int test_hybrid_snat_v4_zero_subnet(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr ip4 = { .protocol = IPPROTO_TCP };
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	test_init();

	/* No subnet entries -> both return subnet_id=0 */
	ipcache_v4_add_entry(IPV4_DST, 0, REMOTE_NODE_ID, 0, 0);
	ipcache_v4_add_entry(IPV4_SRC, 0, LOCAL_NODE_ID, 0, 0);

	tuple.daddr = IPV4_DST;
	tuple.saddr = IPV4_SRC;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.sport = bpf_htons(12345);
	tuple.dport = bpf_htons(443);
	tuple.flags = NAT_DIR_EGRESS;

	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};

	ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
	assert(ret == NAT_NEEDED);
	assert(target.addr == IPV4_MASQUERADE);

	test_finish();
	return 0;
}

/* Test 4: remote_node_masquerade=true overrides hybrid skip */
CHECK("tc", "hybrid_snat_v4_remote_masq_override")
int test_hybrid_snat_v4_remote_masq_override(__maybe_unused struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr ip4 = { .protocol = IPPROTO_TCP };
	fraginfo_t fraginfo = 0;
	int l4_off = 0, ret;

	test_init();

	/* Same subnet, but remote_node_masquerade=true */
	subnet_v4_add_entry(IPV4_SRC, 100);
	subnet_v4_add_entry(IPV4_DST, 100);
	ipcache_v4_add_entry(IPV4_DST, 0, REMOTE_NODE_ID, 0, 0);

	/* Override config for this test */
	ASSIGN_CONFIG(bool, enable_remote_node_masquerade, true)

	tuple.daddr = IPV4_DST;
	tuple.saddr = IPV4_SRC;
	tuple.nexthdr = IPPROTO_TCP;
	tuple.sport = bpf_htons(12345);
	tuple.dport = bpf_htons(443);
	tuple.flags = NAT_DIR_EGRESS;

	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};

	ret = snat_v4_needs_masquerade(ctx, &tuple, &ip4, fraginfo, l4_off, &target);
	assert(ret == NAT_NEEDED);
	assert(target.addr == IPV4_MASQUERADE);

	test_finish();
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");