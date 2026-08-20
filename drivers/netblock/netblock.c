// SPDX-License-Identifier: GPL-2.0
/*
 * netblock - UID 级联网阻止 (独立内核模块)
 *
 * 骨架参考 ReKernel-X (Sakion Team / myflavor): hashmap UID 管理 + for_each_net
 * 注册 netfilter hooks + SOCK_INODE 获取 socket 属主 UID
 *
 * 原理: netfilter LOCAL_OUT hook, 检查 socket 属主 UID 是否在阻止列表
 *       → 是则 NF_DROP 静默丢弃 (TCP+UDP, IPv4+IPv6 全覆盖, 零响应包)
 *       O(1) hashmap 查找, 业界标准做法 (与 netd 防火墙同层级)
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

/* ==================== netfilter hook ==================== */

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
	__netblock_unregister();
	netblock_uid_clear();
	pr_info("netblock: unloaded\n");
}

module_init(netblock_init);
module_exit(netblock_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ReSukiSU-Ultra");
MODULE_DESCRIPTION("netblock - UID level network blocking (netfilter LOCAL_OUT)");
