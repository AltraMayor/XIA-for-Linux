#
# Makefile for Linux's XIA stack.
#

obj-$(CONFIG_XIA) += xia.o

xia-objs :=	main.o socket.o dag.o locktbl.o list_fib.o fib.o \
		fib_frontend.o route.o output.o vxidty.o

obj-$(CONFIG_XIA_PPAL_AD) += ppal_ad/
obj-$(CONFIG_XIA_PPAL_HID) += ppal_hid/
obj-$(CONFIG_XIA_PPAL_LPM) += ppal_lpm/
obj-$(CONFIG_XIA_PPAL_UNI4ID) += ppal_uni4id/
obj-$(CONFIG_XIA_PPAL_U4ID) += ppal_u4id/
obj-$(CONFIG_XIA_PPAL_XDP) += ppal_xdp/
obj-$(CONFIG_XIA_PPAL_ZF) += ppal_zf/
