/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _CTRL_H_
#define _CTRL_H_

#include <ctrlmsg.h>

typedef int (*ctrlmsg_handler_t)(struct ctrlmsg *, int);

int ctrl_init(void);
void ctrl_fini(void);
int ctrl_sendmsg(struct ctrlmsg *, int, int);

#if defined(OS_USER)
int ctrl_recvmsg(void);
int ctrl_getfd(void);
#endif

#endif /* _CTRL_H_ */
