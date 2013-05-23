/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <linux/version.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <service.h>
#include <serval_sock.h>
#include "log.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#define proc_net init_net.proc_net
#endif

#define SERVAL_PROC_DIR "serval"
#define SERVAL_PROC_DBG "dbg"
#define SERVAL_PROC_FILE_SERVICE_TBL "service_table"
#define SERVAL_PROC_FILE_FLOW_TBL "flow_table"

static struct proc_dir_entry *serval_dir = NULL;

static void *service_table_seq_start(struct seq_file *seq, loff_t *pos)
{
        service_table_iterator_t *iter = seq->private;
        
        service_table_iterator_init(iter);

        if (*pos == 0)
                return SEQ_START_TOKEN;
        return NULL;
}

static void service_table_seq_stop(struct seq_file *seq, void *v)
{
        service_table_iterator_t *iter = seq->private;
        service_table_iterator_destroy(iter);
}

static void *service_table_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        service_table_iterator_t *iter = seq->private;
        ++*pos;
        return service_table_iterator_next(iter);
}

static int service_table_seq_show(struct seq_file *seq, void *v)
{
        char buf[1000];
        int len;
       
        if (v == SEQ_START_TOKEN) {
                len = service_table_print_header(buf, sizeof(buf));
        } else {
                struct service_entry *se = (struct service_entry *)v;
                len = service_entry_print(se, buf, sizeof(buf));
        }

        seq_write(seq, buf, len);

        return 0;
}

static const struct seq_operations service_table_seq_ops = {
        .start = service_table_seq_start,
        .next  = service_table_seq_next,
        .stop  = service_table_seq_stop,
        .show  = service_table_seq_show,
};

static int service_table_seq_open(struct inode *inode, struct file *file)
{
        return seq_open_private(file, &service_table_seq_ops, 
                                sizeof(service_table_iterator_t));
}

static const struct file_operations service_table_fops = {
        .owner   = THIS_MODULE,
        .open    = service_table_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release_private,
};

static void *flow_table_seq_start(struct seq_file *seq, loff_t *pos)
{
        struct sock_list_iterator *iter = seq->private;

        sock_list_iterator_init(iter);

        if (*pos == 0)
                return SEQ_START_TOKEN;
        return NULL;
}

static void flow_table_seq_stop(struct seq_file *seq, void *v)
{
        struct sock_list_iterator *iter = seq->private;
        sock_list_iterator_destroy(iter);
}

static void *flow_table_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        struct sock_list_iterator *iter = seq->private;
        ++*pos;
        return sock_list_iterator_next(iter);
}

static int flow_table_seq_show(struct seq_file *seq, void *v)
{
        char buf[1000];
        int len;

        if (v == SEQ_START_TOKEN) {
                len = serval_sock_flow_print_header(buf, sizeof(buf));
        } else {
                struct sock *sk = (struct sock *)v;
                len = serval_sock_flow_print(sk, buf, sizeof(buf));
        }

        seq_write(seq, buf, len);

        return 0;
}

static const struct seq_operations flow_table_seq_ops = {
        .start = flow_table_seq_start,
        .next  = flow_table_seq_next,
        .stop  = flow_table_seq_stop,
        .show  = flow_table_seq_show,
};

static int flow_table_seq_open(struct inode *inode, struct file *file)
{
        return seq_open_private(file, &flow_table_seq_ops,
                                sizeof(struct sock_list_iterator));
}

static const struct file_operations flow_table_fops = {
        .owner   = THIS_MODULE,
        .open    = flow_table_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release_private,
};

/*
  Debug output through /proc/serval/dbg based on linux kernel
  /proc/kmsg

*/
extern wait_queue_head_t log_wait;

static int dbg_open(struct inode *inode, struct file *file)
{
	return do_log(LOG_ACTION_OPEN, NULL, 0, LOG_FROM_FILE);
}

static int dbg_release(struct inode *inode, struct file *file)
{
	(void) do_log(LOG_ACTION_CLOSE, NULL, 0, LOG_FROM_FILE);
	return 0;
}

static ssize_t dbg_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	if ((file->f_flags & O_NONBLOCK) &&
	    !do_log(LOG_ACTION_SIZE_UNREAD, NULL, 0, LOG_FROM_FILE))
		return -EAGAIN;
	return do_log(LOG_ACTION_READ, buf, count, LOG_FROM_FILE);
}

static unsigned int dbg_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &log_wait, wait);
	if (do_log(LOG_ACTION_SIZE_UNREAD, NULL, 0, LOG_FROM_FILE))
		return POLLIN | POLLRDNORM;
	return 0;
}

static const struct file_operations proc_dbg_fops = {
	.read		= dbg_read,
	.poll		= dbg_poll,
	.open		= dbg_open,
	.release	= dbg_release,
	.llseek		= generic_file_llseek,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
static inline 
struct proc_dir_entry *proc_create(const char *name, mode_t mode, 
                                   struct proc_dir_entry *parent,
                                   const struct file_operations *proc_fops)
{
        struct proc_dir_entry *proc;

        proc = create_proc_entry(name, mode, parent);

        if (proc) {
                proc->proc_fops = proc_fops;
        }

        return proc;
}
#endif

int proc_init(void)
{
        struct proc_dir_entry *proc;
        int ret = -ENOMEM;

        serval_dir = proc_mkdir(SERVAL_PROC_DIR, proc_net);

	if (!serval_dir) {
                return -ENOMEM;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
	serval_dir->owner = THIS_MODULE;
#endif
      
	proc = proc_create(SERVAL_PROC_DBG, S_IRUGO, serval_dir, 
                           &proc_dbg_fops);

        if (!proc)
                goto fail_dbg;

        proc = proc_create(SERVAL_PROC_FILE_SERVICE_TBL, 
                           S_IRUGO, 
                           serval_dir, 
                           &service_table_fops);
        
        if (!proc)
                goto fail_service_tbl;

        proc = proc_create(SERVAL_PROC_FILE_FLOW_TBL,
                           S_IRUGO, 
                           serval_dir, 
                           &flow_table_fops);

        if (!proc)
                goto fail_flow_tbl;
        
        ret = 0;
out:        
        return ret;

fail_flow_tbl:
        remove_proc_entry(SERVAL_PROC_FILE_SERVICE_TBL, serval_dir);
fail_service_tbl:
        remove_proc_entry(SERVAL_PROC_DBG, serval_dir);
fail_dbg:
        remove_proc_entry(SERVAL_PROC_DIR, proc_net);
        goto out;
}

void proc_fini(void)
{
        if (!serval_dir)
                return;

        remove_proc_entry(SERVAL_PROC_FILE_SERVICE_TBL, serval_dir);
        remove_proc_entry(SERVAL_PROC_FILE_FLOW_TBL, serval_dir);
        remove_proc_entry(SERVAL_PROC_DBG, serval_dir);
	remove_proc_entry(SERVAL_PROC_DIR, proc_net);
}
