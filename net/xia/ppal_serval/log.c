/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <debug.h>
#include "log.h"

/* This log implementation is heavily based on the Linux kernel's
 * syslog implementation. */
#define LOG_BUF_SHIFT 14
#define __LOG_BUF_LEN	(1 << LOG_BUF_SHIFT)

#define LOG_BUF_MASK (log_buf_len-1)
#define LOG_BUF(idx) (log_buf[(idx) & LOG_BUF_MASK])

static DEFINE_SPINLOCK(logbuf_lock);
/*
 * The indices into log_buf are not constrained to log_buf_len - they
 * must be masked before subscripting
 */
static unsigned log_start; /* Index into log_buf: next char to be read
			    * by syslog() */
static unsigned log_end; /* Index into log_buf:
			  * most-recently-written-char + 1 */

static char __log_buf[__LOG_BUF_LEN];
static char *log_buf = __log_buf;
static int log_buf_len = __LOG_BUF_LEN;
static unsigned logged_chars; /* Number of chars produced since last
			       * read+clear operation */

DECLARE_WAIT_QUEUE_HEAD(log_wait);

int do_log(int type, char __user *buf, size_t len, int from_file)
{
	unsigned i;
	char c;
	int error = 0;

	switch (type) {
	case LOG_ACTION_CLOSE:	/* Close log */
		break;
	case LOG_ACTION_OPEN:	/* Open log */
		break;
	case LOG_ACTION_READ:	/* Read from log */
		error = -EINVAL;
		if (!buf || len < 0)
			goto out;
		error = 0;
		if (!len)
			goto out;
		if (!access_ok(VERIFY_WRITE, buf, len)) {
			error = -EFAULT;
			goto out;
		}
		error = wait_event_interruptible(log_wait,
						 (log_start - log_end));
		if (error)
			goto out;
		i = 0;
		spin_lock_irq(&logbuf_lock);
		while (!error && (log_start != log_end) && i < len) {
			c = LOG_BUF(log_start);
			log_start++;
			spin_unlock_irq(&logbuf_lock);
			error = __put_user(c,buf);
			buf++;
			i++;
			cond_resched();
			spin_lock_irq(&logbuf_lock);
		}
		spin_unlock_irq(&logbuf_lock);
		if (!error)
			error = i;
		break;
	/* Number of chars in the log buffer */
	case LOG_ACTION_SIZE_UNREAD:
		error = log_end - log_start;
		break;
	default:
		error = -EINVAL;
		break;
	}
out:
	return error;
}

static void emit_log_char(const char c)
{
	LOG_BUF(log_end) = c;
	log_end++;
	if (log_end - log_start > log_buf_len)
		log_start = log_end - log_buf_len;
	if (logged_chars < log_buf_len)
		logged_chars++;
}

/* cpu currently holding logbuf_lock */
static volatile unsigned int printk_cpu = UINT_MAX;
static char printk_buf[1024];
static int new_text_line = 1;
static int log_time = 1;

/*
  Basically stolen from Linux kernel's printk

  TODO: Handle log levels.

*/
int log_vprintk(const char *levelstr, const char *func,
		const char *fmt, va_list args)
{
	int printed_len = 0;
	int this_cpu;
        unsigned long flags;
	char *p;

	preempt_disable();
	this_cpu = smp_processor_id();

	lockdep_off();
	spin_lock_irqsave(&logbuf_lock, flags);
	printk_cpu = this_cpu;

	/* Emit the output into the temporary buffer */
	printed_len += vscnprintf(printk_buf + printed_len,
				  sizeof(printk_buf) - printed_len, fmt, args);

	p = printk_buf;

	/*
	 * Copy the output into log_buf.  If the caller didn't provide
	 * appropriate log level tags, we insert them here
	 */
	for ( ; *p; p++) {
		if (new_text_line) {
			const char *lp;

			new_text_line = 0;

			if (log_time) {
				/* Follow the token with the time */
				char tbuf[50], *tp;
				unsigned tlen;
				unsigned long long t;
				unsigned long nanosec_rem;

				t = cpu_clock(printk_cpu);
				nanosec_rem = do_div(t, 1000000000);
				tlen = sprintf(tbuf, "[%5lu.%06lu] ",
						(unsigned long) t,
						nanosec_rem / 1000);

				for (tp = tbuf; tp < tbuf + tlen; tp++)
					emit_log_char(*tp);
				printed_len += tlen;
			}
			/* Emit log level */
			emit_log_char('[');
			printed_len++;
			for (lp = levelstr; *lp != '\0'; lp++) {
				emit_log_char(*lp);
				printed_len++;
			}

			emit_log_char(']');
			printed_len++;

			for (lp = func; *lp != '\0'; lp++) {
				emit_log_char(*lp);
				printed_len++;
			}

			emit_log_char(':');
			emit_log_char(' ');
			printed_len += 2;

			if (!*p)
				break;
		}

		emit_log_char(*p);
		if (*p == '\n')
			new_text_line = 1;
	}

	wake_up_interruptible(&log_wait);

	spin_unlock_irqrestore(&logbuf_lock, flags);
	lockdep_on();
	preempt_enable();

	return printed_len;
}
