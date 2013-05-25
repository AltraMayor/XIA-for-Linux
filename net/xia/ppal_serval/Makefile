#
# Makefile for Serval principal
#

ccflags-y += -DENABLE_SPLICE

obj-$(CONFIG_XIA_PPAL_SERVAL) += xia_ppal_serval.o

xia_ppal_serval-objs :=	main.o serval_sal.o sysctl_net_serval.o \
	serval_udp.o serval_tcp.o serval_tcp_sock.o serval_tcp_output.o \
	serval_tcp_input.o serval_tcp_cong.o serval_tcp_timer.o \
	serval_tcp_metrics.o
