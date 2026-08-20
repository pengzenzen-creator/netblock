# netblock - UID level network blocking kernel module
# 编译: make  (需要 KDIR 指向 6.6 内核源码, KMI 冻结下 .ko 兼容 6.6 全系)
# 产物: netblock.ko

obj-m := netblock.o

KDIR ?= /home/tees/Tesla_Kernel/build/repo/common
OUT  ?= /home/tees/Tesla_Kernel/build/repo/common/out

all:
	$(MAKE) -C $(KDIR) O=$(OUT) ARCH=arm64 LLVM=1 \
		M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) O=$(OUT) ARCH=arm64 LLVM=1 \
		M=$(CURDIR) clean
	rm -f netblock.ko netblock.o netblock.mod* modules.order Module.symvers
