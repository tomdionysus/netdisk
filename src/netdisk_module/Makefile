CONFIG_MODULE_SIG=n

BINARY      := netdisk
KERNEL      := /lib/modules/$(shell uname -r)/build
ARCH        := $(shell uname -m)
C_FLAGS     := -Wall
KMOD_DIR    := $(shell pwd)
TARGET_PATH := /lib/modules/$(shell uname -r)/kernel/drivers/char

ccflags-y += $(C_FLAGS)

# Specify the object files for the module
obj-m := $(BINARY).o
$(BINARY)-objs := module.o util.o transaction.o process_packet_thread.o receive_thread.o send_thread.o timeout_thread.o aes.o udp_socket.o packet.o netdisk_device.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

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
