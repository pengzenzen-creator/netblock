// SPDX-License-Identifier: GPL-2.0
/*
 * netblock - UID 级联网阻止 (独立内核模块)
 *
 * 骨架参考 ReKernel-X (Sakion Team / myflavor): hashmap UID 管理 + for_each_net
 * 注册 netfilter hooks + SOCK_INODE 获取 socket 属主 UID
 *
 * 原理: TCP 建连时 kprobe 拦截 (tcp_v4/v6_connect) → 直接返回 -ECONNREFUSED
 *       UDP 由 netfilter LOCAL_OUT hook 兜底 → 直接 NF_DROP 静默阻断
 *       零响应包生成, 应用直接断网
 *
 * 控制接口 (sysfs, KSU WebUI 通过它控制):
 *   /sys/kernel/netblock/enabled      写 0/1 启停
 *   /sys/kernel/netblock/add_uid      写 uid 添加阻止
 *   /sys/kernel/netblock/remove_uid   写 uid 移除阻止
 *   /sys/kernel/netblock/clear        写 1 清空
 *   /sys/kernel/netblock/list         读 列出阻止的 uid
 *
 * 仅标准内核 API (netfilter/hashtable/sock), KMI 冻结下 6.6 全系兼容
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <net/sock.h>
#include <net/rtnetlink.h>
#include <linux/kprobes.h>
#include <net/tcp.h>


#define NETBLOCK_HASH_BITS 8

struct netblock_uid {
	uid_t uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(netblock_uid_map, NETBLOCK_HASH_BITS);
static DEFINE_MUTEX(netblock_mutex);
static bool netblock_enabled;

/* ==================== UID 管理 (hashmap, RCU) ==================== */

static bool netblock_uid_blocked(uid_t uid)
{
	struct netblock_uid *entry;
	bool found = false;

	rcu_read_lock();
	hash_for_each_possible_rcu(netblock_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static void netblock_uid_add(uid_t uid)
{
	struct netblock_uid *entry;
	bool found = false;

	mutex_lock(&netblock_mutex);
	hash_for_each_possible(netblock_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			found = true;
			break;
		}
	}
	if (!found) {
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			hash_add_rcu(netblock_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&netblock_mutex);
}

static void netblock_uid_del(uid_t uid)
{
	struct netblock_uid *entry;

	mutex_lock(&netblock_mutex);
	hash_for_each_possible(netblock_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&netblock_mutex);
}

static void netblock_uid_clear(void)
{
	struct netblock_uid *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&netblock_mutex);
	hash_for_each_safe(netblock_uid_map, bkt, tmp, entry, hnode) {
		hash_del_rcu(&entry->hnode);
		kfree_rcu(entry, rcu);
	}
	mutex_unlock(&netblock_mutex);
}

/* ==================== socket 层拦截 (kprobe tcp_v4/v6_connect) ====================
 * TCP 建连时检查一次 UID → 命中直接返回 -ECONNREFUSED
 * 零每包开销 (仅建连一次), 应用立即感知断网
 */
static int netblock_connect_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* arm64: sock 在 x0, addr 在 x1 */
	struct sock *sk = (struct sock *)regs->regs[0];
	uid_t uid;

	if (!netblock_enabled)
		return 0;
	if (!sk || !sk->sk_socket)
		return 0;

	uid = SOCK_INODE(sk->sk_socket)->i_uid.val;
	if (uid < 10000)
		return 0;
	if (netblock_uid_blocked(uid)) {
		/* 返回非 0 跳过原函数, 直接返回 -ECONNREFUSED */
		regs->regs[0] = -ECONNREFUSED;
		return 1;
	}
	return 0;
}

static struct kprobe netblock_kp_tcp4 = {
	.symbol_name = "tcp_v4_connect",
	.pre_handler = netblock_connect_pre,
};
#ifdef CONFIG_IPV6
static struct kprobe netblock_kp_tcp6 = {
	.symbol_name = "tcp_v6_connect",
	.pre_handler = netblock_connect_pre,
};
#endif

static int netblock_kprobes_register(void)
{
	int ret;

	ret = register_kprobe(&netblock_kp_tcp4);
	if (ret)
		pr_info("netblock: tcp_v4_connect kprobe failed (%d), TCP 走 netfilter
", ret);
#ifdef CONFIG_IPV6
	ret = register_kprobe(&netblock_kp_tcp6);
	if (ret)
		pr_info("netblock: tcp_v6_connect kprobe failed (%d), TCP6 走 netfilter
", ret);
#endif
	return 0;
}

static void netblock_kprobes_unregister(void)
{
	unregister_kprobe(&netblock_kp_tcp4);
#ifdef CONFIG_IPV6
	unregister_kprobe(&netblock_kp_tcp6);
#endif
}

/* ==================== netfilter hook (UDP 兜底) ==================== */

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

	uid = netblock_sock2uid(sk);
	if (uid < 10000)
		return NF_ACCEPT; /* 不拦系统/root */

	if (netblock_uid_blocked(uid))
		return NF_DROP; /* 直接静默丢包阻断, 不生成任何响应 */

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

static bool netblock_hook_registered;

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
	netblock_hook_registered = true;
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
	struct netblock_uid *entry;
	int bkt;
	int off = 0;

	rcu_read_lock();
	hash_for_each_rcu(netblock_uid_map, bkt, entry, hnode)
		off += sysfs_emit_at(buf, off, "%u\n", entry->uid);
	rcu_read_unlock();
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

	hash_init(netblock_uid_map);
	netblock_enabled = false;

	netblock_kprobes_register();
	ret = netblock_register();
	if (ret)
		return ret;

	netblock_kobj = kobject_create_and_add("netblock", kernel_kobj);
	if (!netblock_kobj) {
		__netblock_unregister();
		return -ENOMEM;
	}
	ret = sysfs_create_group(netblock_kobj, &netblock_attr_group);
	if (ret) {
		kobject_put(netblock_kobj);
		__netblock_unregister();
		return ret;
	}

	pr_info("netblock: loaded (sysfs: /sys/kernel/netblock)\n");
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
MODULE_DESCRIPTION("netblock - UID level network blocking (netfilter LOCAL_OUT)");
