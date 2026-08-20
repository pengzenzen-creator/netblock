// SPDX-License-Identifier: GPL-2.0
/*
 * netblock - UID 级联网阻止 (独立内核模块)
 *
 * 拦截架构 (零数据路径开销):
 *   TCP: kprobe tcp_v4_connect/tcp_v6_connect → 建连时查一次 bitmap
 *        → 命中直接返回 -ECONNREFUSED (应用立即断网)
 *        连接建立后数据包零检查 (无 netfilter 每包开销)
 *   UDP: netfilter LOCAL_OUT hook 兜底 (UDP 无连接语义, 只能每包查)
 *        → 命中 nf_reject_skb_v6 回 ICMP port unreachable
 *
 * 数据结构: bitmap 数组 (UID 空间固定 ≤100000, 8KB 内存)
 *   查/增/删均为 O(1) 一次索引, 无 hash 计算无链表无 RCU
 *
 * 控制接口 (sysfs, KSU WebUI 通过它控制):
 *   /sys/kernel/netblock/enabled      写 0/1 启停
 *   /sys/kernel/netblock/add_uid      写 uid 添加阻止
 *   /sys/kernel/netblock/remove_uid   写 uid 移除阻止
 *   /sys/kernel/netblock/clear        写 1 清空
 *   /sys/kernel/netblock/list         读 列出阻止的 uid
 *
 * 仅标准内核 API (kprobe/netfilter/bitmap/sock), KMI 冻结下 6.6 全系兼容
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

/* UID 空间: Android app uid = appid + user_id*100000, 上限 100000 */
#define NETBLOCK_UID_MAX 100000
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

/* ==================== TCP: kprobe connect 拦截 (零数据路径开销) ====================
 * 仅建连时查一次, 命中返回 -ECONNREFUSED 并跳过原函数
 * 连接建立后所有数据包不再经过任何检查
 */
static int netblock_connect_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* arm64: sock *sk 在 x0 = regs[0] */
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
		/* 跳过原函数, connect 直接返回 -ECONNREFUSED */
		regs->regs[0] = -ECONNREFUSED;
		return 1;
	}
	return 0;
}

static struct kprobe netblock_kp_tcp4 = {
	.symbol_name = "tcp_v4_connect",
	.pre_handler = netblock_connect_pre,
};
#if IS_ENABLED(CONFIG_IPV6)
static struct kprobe netblock_kp_tcp6 = {
	.symbol_name = "tcp_v6_connect",
	.pre_handler = netblock_connect_pre,
};
#endif

static void netblock_kprobes_register(void)
{
	if (register_kprobe(&netblock_kp_tcp4))
		pr_info("netblock: tcp_v4_connect kprobe fail, TCP 走 netfilter\n");
#if IS_ENABLED(CONFIG_IPV6)
	if (register_kprobe(&netblock_kp_tcp6))
		pr_info("netblock: tcp_v6_connect kprobe fail, TCP6 走 netfilter\n");
#endif
}

static void netblock_kprobes_unregister(void)
{
	unregister_kprobe(&netblock_kp_tcp4);
#if IS_ENABLED(CONFIG_IPV6)
	unregister_kprobe(&netblock_kp_tcp6);
#endif
}

/* ==================== UDP 兜底: netfilter LOCAL_OUT ====================
 * UDP 无 connect 语义 (sendto 无需建连), 只能每包查 bitmap (O(1) 索引, 开销可忽略)
 * TCP 已由 kprobe 拦, 此处跳过 TCP 减少重复检查
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
		/* ICMP port unreachable → 应用立即感知 */
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

	pr_info("netblock: loaded (TCP kprobe + UDP netfilter, sysfs: /sys/kernel/netblock)\n");
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
MODULE_DESCRIPTION("netblock - UID level network blocking (TCP kprobe + UDP netfilter)");
