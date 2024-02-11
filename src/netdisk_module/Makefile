CONFIG_MODULE_SIG=n

BINARY      := netdisk
KERNEL      := /lib/modules/$(shell uname -r)/build
ARCH        := $(shell uname -m)
EXTRA_CFLAGS := -I$(PWD)/../ -Wall -DIS_KERNEL=1
KMOD_DIR    := $(shell pwd)
TARGET_PATH := /lib/modules/$(shell uname -r)/kernel/drivers/char

# Specify the object files for the module
obj-m := $(BINARY).o
$(BINARY)-objs := ../shared/packet.o module.o util.o transaction.o send_thread.o receive_thread.o aes.o packet_kernel.o netdisk_device.o

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean

install:
	cp $(BINARY).ko $(TARGET_PATH)

load:
	modprobe $(BINARY)

remove:
	rm $(TARGET_PATH)/$(BINARY).ko

unload:
	rmmod -v $(BINARY)

log:
	echo "7 7" > /proc/sys/kernel/printk
	dmesg -r | grep netdisk

reset: clean remove unload
