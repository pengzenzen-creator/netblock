#!/system/bin/sh
# NetBlock 安装时初始化持久化文件
MODDIR=${0%/*}
# 确保持久化文件永远存在 (弱持久化根源: 文件可能不存在)
[ -f "$MODDIR/blocked.list" ] || : > "$MODDIR/blocked.list"
[ -f "$MODDIR/enabled" ] || echo 0 > "$MODDIR/enabled"
chmod 644 "$MODDIR/blocked.list" "$MODDIR/enabled"
