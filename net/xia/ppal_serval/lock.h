/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LOCK_H
#define _LOCK_H

#include <platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/spinlock.h>

#define spin_lock_destroy(x)
#define rwlock_destroy(x)

#endif /* OS_LINUX_KERNEL */

#if defined(OS_USER)
#include <pthread.h>

typedef pthread_mutex_t spinlock_t;

#if defined(ENABLE_DEBUG_LOCKS)
#include <serval/debug.h>
#endif

static inline int __pthread_mutex_lock(pthread_mutex_t *m, 
                                       const char *func,
                                       unsigned int line) 
{                                            
        int ret;

#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("locking %p %s %u\n", m, func, line);
#endif
        ret = pthread_mutex_lock(m);
#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("locked %p\n", m);
#endif
        return ret;
}

static inline int __pthread_mutex_unlock(pthread_mutex_t *m) 
{
        int ret;

#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("unlocking %p\n", m);
#endif
        ret = pthread_mutex_unlock(m);
#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("unlocked %p\n", m);
#endif
        return ret;
}

static inline int __pthread_rwlock_wrlock(pthread_rwlock_t *m,
                                          const char *func,
                                          unsigned int line) 
{
        int ret;

#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("locking %p %s %u\n", m, func, line);
#endif
        ret = pthread_rwlock_wrlock(m);
#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("locked %p\n", m);
#endif
        return ret;
}

static inline int __pthread_rwlock_rdlock(pthread_rwlock_t *m,
                                          const char *func,
                                          unsigned int line) 
{
        int ret;

#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("locking %p %s %u\n", m, func, line);
#endif
        ret = pthread_rwlock_rdlock(m);
#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("locked %p\n", m);
#endif
        return ret;
}

static inline int __pthread_rwlock_unlock(pthread_rwlock_t *m) 
{
        int ret;

#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("unlocking %p\n", m);
#endif
        ret = pthread_rwlock_unlock(m);
#if defined(ENABLE_DEBUG_LOCKS)
        LOG_DBG("unlocked %p\n", m);
#endif
        return ret;
}

#define SPIN_LOCK_UNLOCKED PTHREAD_MUTEX_INITIALIZER

#define DEFINE_SPINLOCK(x) spinlock_t x = PTHREAD_MUTEX_INITIALIZER

#define spin_lock_init(x) pthread_mutex_init(x, NULL)
#define spin_lock_init_recursive(x) {                              \
	pthread_mutexattr_t attr;                                  \
	pthread_mutexattr_init(&attr);                             \
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); \
	pthread_mutex_init(&mutex, &attr);                         \
	pthread_mutexattr_destroy(&attr); }
#define spin_lock_destroy(x) pthread_mutex_destroy(x)
#define spin_lock(x) __pthread_mutex_lock(x, __func__, __LINE__)
#define spin_trylock(x) pthread_mutex_trylock(x)
#define spin_unlock(x) __pthread_mutex_unlock(x)

#define spin_lock_bh(x) __pthread_mutex_lock(x, __func__, __LINE__)
#define spin_trylock_bh(x) pthread_mutex_trylock(x)
#define spin_unlock_bh(x) __pthread_mutex_unlock(x)

#define spin_lock_irqsave(x, flags) __pthread_mutex_lock(x, __func__, __LINE__)
#define spin_unlock_irqrestore(x, flags) __pthread_mutex_unlock(x)

typedef pthread_rwlock_t rwlock_t;

#define __RW_LOCK_UNLOCKED(x) PTHREAD_RWLOCK_INITIALIZER
#define DEFINE_RWLOCK(x) rwlock_t x = PTHREAD_RWLOCK_INITIALIZER

#define rwlock_init(x) pthread_rwlock_init(x, NULL)
#define rwlock_destroy(x) pthread_rwlock_destroy(x)
#define write_lock(x) __pthread_rwlock_wrlock(x, __func__, __LINE__)
#define read_lock(x) __pthread_rwlock_rdlock(x, __func__, __LINE__)
#define write_lock_bh(x) __pthread_rwlock_wrlock(x, __func__, __LINE__)
#define read_lock_bh(x) __pthread_rwlock_rdlock(x, __func__, __LINE__)
#define write_trylock(x) pthread_rwlock_trywrlock(x)
#define read_trylock(x) pthread_rwlock_tryrdlock(x)
#define write_trylock_bh(x) pthread_rwlock_trywrlock(x)
#define read_trylock_bh(x) pthread_rwlock_tryrdlock(x)
#define write_unlock(x) __pthread_rwlock_unlock(x)
#define read_unlock(x) __pthread_rwlock_unlock(x)
#define write_unlock_bh(x) __pthread_rwlock_unlock(x)
#define read_unlock_bh(x) __pthread_rwlock_unlock(x)

#define local_bh_disable()
#define local_bh_enable()

#endif /* OS_USER */

#endif /* _LOCK_H */
