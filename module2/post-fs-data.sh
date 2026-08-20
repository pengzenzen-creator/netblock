#!/system/bin/sh
MODDIR=${0%/*}

# 加载 netblock.ko (KMI 冻结, 6.6 全系兼容)
for mod in "$MODDIR"/system/lib/modules/netblock.ko; do
    if [ -f "$mod" ]; then
        insmod "$mod" 2>/dev/null && log -t NetBlock -p i "netblock.ko loaded"
    fi
done

# 确保 sysfs 目录权限 (KSU WebUI 读写)
if [ -d /sys/kernel/netblock ]; then
    chmod 666 /sys/kernel/netblock/* 2>/dev/null
fi

# 读取持久化配置 (enabled 状态 + UID 列表)
CONF="$MODDIR/netblock.conf"
if [ -f "$CONF" ]; then
    . "$CONF"
    [ "$NETBLOCK_ENABLED" = "1" ] && echo 1 > /sys/kernel/netblock/enabled
    for uid in $NETBLOCK_UIDS; do
        echo "$uid" > /sys/kernel/netblock/add_uid 2>/dev/null
    done
fi
