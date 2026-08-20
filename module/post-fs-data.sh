#!/system/bin/sh
MODDIR=${0%/*}

# 1. 加载内核模块
if [ -f "$MODDIR/netblock.ko" ]; then
  insmod "$MODDIR/netblock.ko" 2>/dev/null || echo 1 > "$MODDIR/ko-failed"
fi

# 2. 恢复持久化的阻止列表 (WebUI 增删时同步写 blocked.list)
if [ -f "$MODDIR/blocked.list" ]; then
  while read -r uid; do
    [ -n "$uid" ] && echo "$uid" > /sys/kernel/netblock/add_uid 2>/dev/null
  done < "$MODDIR/blocked.list"
fi

# 3. 恢复启停状态
if [ -f "$MODDIR/enabled" ] && [ "$(cat "$MODDIR/enabled" 2>/dev/null)" = "1" ]; then
  echo 1 > /sys/kernel/netblock/enabled 2>/dev/null
fi
