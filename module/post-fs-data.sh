#!/system/bin/sh
MODDIR=${0%/*}
if [ -f "$MODDIR/netblock.ko" ]; then
  insmod "$MODDIR/netblock.ko" 2>/dev/null || echo 1 > "$MODDIR/ko-failed"
fi
