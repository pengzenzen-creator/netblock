// SPDX-License-Identifier: GPL-2.0
/*
 * netblock - UID 级联网阻止 (独立内核模块)
 *
 * 拦截架构 (零数据路径开销, 等效 LSM socket_connect):
 *   connect() 统一挂点: kprobe inet_stream_connect / inet_dgram_connect
 *   / ip6_datagram_connect (覆盖 TCP+UDP, IPv4+IPv6 全部 connect 系统调用)
 *   → 建连时查一次 bitmap, 命中直接返回 -ECONNREFUSED (应用立即断网)
 *   连接建立后数据路径零检查
 *
 *   UDP 未 connect (sendto) 兜底: netfilter LOCAL_OUT (Android 罕见路径)
 *
 * 数据结构: bitmap 数组 (Android uid 上限 user_id*100000+appid ≤ 10^7)
 *   O(1) 一次索引, 无 hash 无链表无 RCU, 静态 1.25MB
 *
 * 控制接口 (sysfs, KSU WebUI 通过它控制):
 *   /sys/kernel/netblock/enabled      写 0/1 启停
 *   /sys/kernel/netblock/add_uid      写 uid 添加阻止
 *   /sys/kernel/netblock/remove_uid   写 uid 移除阻止
 *   /sys/kernel/netblock/clear        写 1 清空
 *   /sys/kernel/netblock/list         读 列出阻止的 uid
 *
 * 说明: Linux 6.6 security_add_hooks 为 __init, LSM 栈启动时固定,
 * 可加载模块无法注册 LSM hook → 用 kprobe 挂 connect 统一入口等效实现
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitmap.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <net/sock.h>
#include <net/rtnetlink.h>
#include <linux/icmp.h>
#include <net/netfilter/ipv4/nf_reject.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/icmpv6.h>
#include <net/netfilter/ipv6/nf_reject.h>
#endif

/* Android uid = user_id*100000 + appid, 多用户下可达 ~10^7 */
#define NETBLOCK_UID_MAX 10000000
static DECLARE_BITMAP(netblock_bitmap, NETBLOCK_UID_MAX);
static bool netblock_enabled;

/* ==================== UID 管理 (bitmap, O(1)) ==================== */

static inline bool netblock_uid_blocked(uid_t uid)
{
	if (uid >= NETBLOCK_UID_MAX)
		return false;
	return test_bit(uid, netblock_bitmap);
}

static void netblock_uid_add(uid_t uid)
{
	if (uid < NETBLOCK_UID_MAX)
		set_bit(uid, netblock_bitmap);
}

static void netblock_uid_del(uid_t uid)
{
	if (uid < NETBLOCK_UID_MAX)
		clear_bit(uid, netblock_bitmap);
}

static void netblock_uid_clear(void)
{
	bitmap_zero(netblock_bitmap, NETBLOCK_UID_MAX);
}

/* ==================== connect() 拦截 (等效 LSM socket_connect) ====================
 * kprobe 挂三个 connect 统一入口: 一个 pre_handler 共用
 * 参数: arm64 x0 = struct sock *sk (inet_stream_connect/inet_dgram_connect
 *       /ip6_datagram_connect 首参均为 struct sock *)
 * 命中 → 跳过原函数返回 -ECONNREFUSED, 应用立即感知断网
 * 数据路径零开销 (仅建连时一次)
 */
static int netblock_connect_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sock *sk = (struct sock *)regs->regs[0];
	uid_t uid;

	if (!netblock_enabled)
		return 0;
	if (!sk || !sk->sk_socket)
		return 0;

	uid = SOCK_INODE(sk->sk_socket)->i_uid.val;
	if (uid < 10000)
		return 0; /* 不拦系统/root */

	if (netblock_uid_blocked(uid)) {
		regs->regs[0] = -ECONNREFUSED;
		return 1; /* 跳过原函数 */
	}
	return 0;
}

static struct kprobe netblock_kp_stream = {
	.symbol_name = "inet_stream_connect",
	.pre_handler = netblock_connect_pre,
};
static struct kprobe netblock_kp_dgram = {
	.symbol_name = "inet_dgram_connect",
	.pre_handler = netblock_connect_pre,
};
static struct kprobe netblock_kp_dgram6 = {
	.symbol_name = "ip6_datagram_connect",
	.pre_handler = netblock_connect_pre,
};

static void netblock_kprobes_register(void)
{
	if (register_kprobe(&netblock_kp_stream))
		pr_info("netblock: inet_stream_connect kprobe fail\n");
	if (register_kprobe(&netblock_kp_dgram))
		pr_info("netblock: inet_dgram_connect kprobe fail\n");
	if (register_kprobe(&netblock_kp_dgram6))
		pr_info("netblock: ip6_datagram_connect kprobe fail\n");
}

static void netblock_kprobes_unregister(void)
{
	unregister_kprobe(&netblock_kp_stream);
	unregister_kprobe(&netblock_kp_dgram);
	unregister_kprobe(&netblock_kp_dgram6);
}

/* ==================== UDP sendto 兜底: netfilter LOCAL_OUT ====================
 * UDP 未 connect 时 (sendto 不经过 connect 挂点), 只能每包查 (O(1))
 * TCP 已由 kprobe 拦, 此处跳过
 */
static inline uid_t netblock_sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	return 0;
}

static unsigned int netblock_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	struct sock *sk;
	uid_t uid;

	if (!netblock_enabled)
		return NF_ACCEPT;
	if (!skb || !state)
		return NF_ACCEPT;
	if (state->hook != NF_INET_LOCAL_OUT)
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;

	if (sk->sk_protocol == IPPROTO_TCP)
		return NF_ACCEPT; /* TCP 已由 kprobe 拦 */

	uid = netblock_sock2uid(sk);
	if (uid < 10000)
		return NF_ACCEPT; /* 不拦系统/root */

	if (netblock_uid_blocked(uid)) {
		if (state->pf == NFPROTO_IPV4)
			return nf_reject_skb_v4(state->net, skb, state,
						ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
#if IS_ENABLED(CONFIG_IPV6)
		else if (state->pf == NFPROTO_IPV6)
			return nf_reject_skb_v6(state->net, skb, state,
						ICMPV6_PORT_UNREACH, ICMPV6_PORT_UNREACH);
#endif
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops netblock_nf_ops[] = {
	{
		.hook     = netblock_hook,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER - 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = netblock_hook,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_FILTER - 1,
	}
#endif
};

static void __netblock_unregister(void)
{
	struct net *net;

	rtnl_lock();
	for_each_net(net)
		nf_unregister_net_hooks(net, netblock_nf_ops,
					 ARRAY_SIZE(netblock_nf_ops));
	rtnl_unlock();
}

static int netblock_register(void)
{
	struct net *net;
	int rc = 0;

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, netblock_nf_ops,
					   ARRAY_SIZE(netblock_nf_ops));
		if (rc) {
			pr_err("netblock: register hooks failed on net=%p rc=%d\n",
			       net, rc);
			break;
		}
	}
	rtnl_unlock();

	if (rc) {
		__netblock_unregister();
		return rc;
	}
	return 0;
}

/* ==================== sysfs 接口 ==================== */

static struct kobject *netblock_kobj;

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "%d\n", netblock_enabled ? 1 : 0);
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int val;

	if (kstrtouint(buf, 10, &val))
		return -EINVAL;
	netblock_enabled = val != 0;
	return count;
}

static ssize_t add_uid_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int uid;

	if (kstrtouint(buf, 10, &uid))
		return -EINVAL;
	netblock_uid_add(uid);
	return count;
}

static ssize_t remove_uid_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	unsigned int uid;

	if (kstrtouint(buf, 10, &uid))
		return -EINVAL;
	netblock_uid_del(uid);
	return count;
}

static ssize_t clear_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	netblock_uid_clear();
	return count;
}

static ssize_t list_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	int off = 0;
	unsigned long idx;

	for_each_set_bit(idx, netblock_bitmap, NETBLOCK_UID_MAX)
		off += sysfs_emit_at(buf, off, "%lu\n", idx);
	return off;
}

static struct kobj_attribute netblock_enabled_attr =
	__ATTR(enabled, 0644, enabled_show, enabled_store);
static struct kobj_attribute netblock_add_uid_attr =
	__ATTR(add_uid, 0200, NULL, add_uid_store);
static struct kobj_attribute netblock_remove_uid_attr =
	__ATTR(remove_uid, 0200, NULL, remove_uid_store);
static struct kobj_attribute netblock_clear_attr =
	__ATTR(clear, 0200, NULL, clear_store);
static struct kobj_attribute netblock_list_attr =
	__ATTR(list, 0444, list_show, NULL);

static struct attribute *netblock_attrs[] = {
	&netblock_enabled_attr.attr,
	&netblock_add_uid_attr.attr,
	&netblock_remove_uid_attr.attr,
	&netblock_clear_attr.attr,
	&netblock_list_attr.attr,
	NULL,
};

static const struct attribute_group netblock_attr_group = {
	.attrs = netblock_attrs,
};

/* ==================== init/exit ==================== */

static int __init netblock_init(void)
{
	int ret;

	bitmap_zero(netblock_bitmap, NETBLOCK_UID_MAX);
	netblock_enabled = false;

	netblock_kprobes_register();

	ret = netblock_register();
	if (ret) {
		netblock_kprobes_unregister();
		return ret;
	}

	netblock_kobj = kobject_create_and_add("netblock", kernel_kobj);
	if (!netblock_kobj) {
		netblock_kprobes_unregister();
		__netblock_unregister();
		return -ENOMEM;
	}
	ret = sysfs_create_group(netblock_kobj, &netblock_attr_group);
	if (ret) {
		kobject_put(netblock_kobj);
		netblock_kprobes_unregister();
		__netblock_unregister();
		return ret;
	}

	pr_info("netblock: loaded (connect kprobe + UDP netfilter, sysfs: /sys/kernel/netblock)\n");
	return 0;
}

static void __exit netblock_exit(void)
{
	sysfs_remove_group(netblock_kobj, &netblock_attr_group);
	kobject_put(netblock_kobj);
	netblock_kprobes_unregister();
	__netblock_unregister();
	netblock_uid_clear();
	pr_info("netblock: unloaded\n");
}

module_init(netblock_init);
module_exit(netblock_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ReSukiSU-Ultra");
MODULE_DESCRIPTION("netblock - UID network blocking (connect kprobe, zero data-path cost)");
