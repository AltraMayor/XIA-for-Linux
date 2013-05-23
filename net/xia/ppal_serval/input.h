/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _INPUT_H_
#define _INPUT_H_

#if defined(OS_USER)
#include <netinet/ip.h>
#elif defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#endif 

enum {
	INPUT_ERROR = -1,
	INPUT_OK, /* Processing OK, packet stolen */
	INPUT_DELIVER, /* Let the packet go through to other stack,
                        * e.g., to normal IP */
	INPUT_DROP, /* Drop packet, do not let it go through to other
                     * stack, e.g., IP */
	INPUT_NO_PROT,
	INPUT_NO_SOCK,
};

#define IS_INPUT_ERROR(val) (val < 0)

#endif /* _INPUT_H_ */
