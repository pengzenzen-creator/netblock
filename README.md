# NetBlock

内核级 UID 联网拦截模块 (netfilter LOCAL_OUT hook)

- **独立 .ko**，不依赖 KernelSU/Magisk 源码修改，KMI 冻结下 6.6 全系兼容
- **DDK 容器编译** (ghcr.io/ylarod/ddk)，与手机内核 KMI 精确匹配
- **sysfs 控制**：`/sys/kernel/netblock/{enabled,add_uid,remove_uid,clear,list}`
- **KSU WebUI**：美观控制界面

## 用法

1. 下载 `NetBlock-*.zip`，KSU/Magisk 管理器刷入
2. 重启后模块自动加载
3. KSU WebUI 控制，或手动：
   ```sh
   echo 1 > /sys/kernel/netblock/enabled       # 启用
   echo 10258 > /sys/kernel/netblock/add_uid   # 阻止 UID 10258
   cat /sys/kernel/netblock/list               # 查看列表
   ```

## 编译 (DDK)

```sh
# GitHub Actions: ddk-lkm.yml (kmi=android15-6.6, ddk_release=20260313)
# 或本地:
# 源码放 /opt/ddk/src/<KMI>/drivers/netblock
make -C /opt/ddk/kdir/<KMI> M=/opt/ddk/src/<KMI>/drivers/netblock CC="clang" modules
```

## 原理

netfilter LOCAL_OUT hook → `SOCK_INODE(sk->sk_socket)->i_uid.val` 取 socket 属主 UID
→ 在阻止列表则 `NF_DROP`。系统/root (uid<10000) 永不拦截。
