#
# Makefile for Serval principal
#

ccflags-y += -I$(srctree)/net/xia/ppal_serval -DENABLE_SPLICE -D__linux__

obj-$(CONFIG_XIA_PPAL_SERVAL) += xia_ppal_serval.o

xia_ppal_serval-objs :=	main.o \
	debug.o delay_queue.o platform.o af_serval.o bst.o service.o \
	ctrl_handler.o serval_sock.o serval_sal.o serval_ipv4.o \
	serval_udp.o serval_tcp.o serval_tcp_sock.o serval_tcp_output.o \
	serval_tcp_input.o serval_tcp_cong.o serval_tcp_timer.o \
	serval_tcp_metrics.o ctrl.o proc.o packet.o log.o \
	udp_encap.o sysctl_net_serval.o inet_to_serval.o
