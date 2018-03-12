# ©

CC_FLAGS = -Wall -Wnounused-result

SOURCE_FILE = fake_hd_sn.c
OBJECT_FILE = $(SOURCE_FILE:.c=.o)
TARGET_FILE = $(SOURCE_FILE:.c=.ko)

KERNEL_PATH = /lib/modules/$(shell uname -r)/build

obj-m := $(OBJECT_FILE)


all:
	$(MAKE) CROSS_COMPILE=$(CROSS) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) clean
	rm -rf Module.symvers *.mod.c *.ko *.o *~
