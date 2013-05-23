/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _WAIT_H_
#define _WAIT_H_

#include <platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/wait.h>
#define UNDEFINE_WAIT(name)
#define UNDECLARE_WAITQUEUE(name)
#else
#include <serval/list.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <limits.h>

typedef struct __wait_queue wait_queue_t;
typedef int (*wait_queue_func_t)(wait_queue_t *wait, 
                                 unsigned mode, int flags, void *key);
int default_wake_function(wait_queue_t *wait, unsigned mode, 
                          int flags, void *key);

struct task_struct {
        pthread_t thread;
};

struct __wait_queue {
	unsigned int flags;
	struct task_struct *private_data;
	wait_queue_func_t func;
	pthread_mutex_t lock;
        int pipefd[2];
	struct list_head thread_list;
};

struct __wait_queue_head {
	pthread_mutex_t lock;
	struct list_head thread_list;
};

typedef struct __wait_queue_head wait_queue_head_t;

#define current ((struct task_struct *)(pthread_self()))

#define WQ_FLAG_EXCLUSIVE 0x1

#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2

#define __WAITQUEUE_INITIALIZER(name, tsk) {				\
	.private_data	= tsk,						\
	.func		= default_wake_function,			\
        .lock           = PTHREAD_MUTEX_INITIALIZER,                    \
        .pipefd	        = { -1, -1 },                                   \
        .thread_list	= { &(name).thread_list, &(name).thread_list } }

#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk);         \
        init_wait(&name)

#define UNDECLARE_WAITQUEUE(name) destroy_wait(name)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= PTHREAD_MUTEX_INITIALIZER,		        \
	.thread_list	= { &(name).thread_list, &(name).thread_list } }

#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

void prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state);
void prepare_to_wait_exclusive(wait_queue_head_t *q,
                               wait_queue_t *wait, int state);
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait);
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, 
                             int sync, void *key);

#define DEFINE_WAIT_FUNC(name, function)				\
	wait_queue_t name = {						\
		.private_data	= current,				\
		.func		= function,				\
		.thread_list	= LIST_HEAD_INIT((name).thread_list),	\
	}; init_wait(&name)

#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
#define UNDEFINE_WAIT(name) destroy_wait(name)

void init_wait(wait_queue_t *w);
void destroy_wait(wait_queue_t *w);

void init_waitqueue_head(wait_queue_head_t *q);
void destroy_waitqueue_head(wait_queue_head_t *q);

static inline int waitqueue_active(wait_queue_head_t *q)
{
        return !list_empty(&q->thread_list);
}

void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new);
void __add_wait_queue_tail(wait_queue_head_t *head, wait_queue_t *new);

void __wake_up(wait_queue_head_t *q, unsigned int mode,
               int nr_exclusive, void *key);
void __wake_up_locked_key(wait_queue_head_t *q, unsigned int mode, void *key);
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode, int nr,
                        void *key);
void __wake_up_locked(wait_queue_head_t *q, unsigned int mode);
void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr);

#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL)

#define wake_up_interruptible(x)                        \
        __wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_nr(x, nr)                 \
        __wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_all(x)                    \
        __wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_sync(x)                   \
        __wake_up_sync((x), TASK_INTERRUPTIBLE, 1)

#define wake_up_poll(x, m)\
        __wake_up(x, TASK_NORMAL, 1, (void *) (m))
#define wake_up_locked_poll(x, m)\
        __wake_up_locked_key((x), TASK_NORMAL, (void *) (m))
#define wake_up_interruptible_poll(x, m)\
        __wake_up(x, TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_interruptible_sync_poll(x, m)\
        __wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *) (m))

/*
 * Used for wake-one threads:
 */
static inline void __add_wait_queue_exclusive(wait_queue_head_t *q,
					      wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue(q, wait);
}

static inline void __add_wait_queue_tail_exclusive(wait_queue_head_t *q,
                                                   wait_queue_t *wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue_tail(q, wait);
}

static inline void __remove_wait_queue(wait_queue_head_t *head,
                                       wait_queue_t *old)
{
	list_del(&old->thread_list);
}

#define set_current_state(x)
#define __set_current_state(x)
#define MAX_SCHEDULE_TIMEOUT LONG_MAX
#define ERESTARTSYS 512

int signal_pending(struct task_struct *task);

signed long schedule_timeout(signed long timeo);
#define schedule(timeo) schedule_timeout(MAX_SCHEDULE_TIMEOUT)

void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait);
void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait);
void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait);

#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})

#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
        UNDEFINE_WAIT(&__wait);                                         \
} while (0)

#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})

#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
        UNDEFINE_WAIT(&__wait);                                         \
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#endif /* OS_LINUX_KERNEL */

#endif /* _WAIT_H_ */
