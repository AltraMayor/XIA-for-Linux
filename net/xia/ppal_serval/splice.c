/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#if defined(ENABLE_SPLICE)
#include <skbuff.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/splice.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pipe_fs_i.h>
#include <linux/wait.h>
#include <net/sock.h>

#define UBUNTU_NON_STANDARD_KERNEL                      \
        ((LINUX_VERSION_CODE == 197144) ||              \
         (LINUX_VERSION_CODE == 197148) ||              \
         (LINUX_VERSION_CODE == 197150) ||              \
         (LINUX_VERSION_CODE == 197157) ||              \
         (LINUX_VERSION_CODE == 197159))
        
/* This is pure unmodified Linux kernel code. It is provided here
 * because the skb_splice_bits() function is not exported in the Linux
 * kernel, and this function is necessary to implement splice support
 * for transport protocols. Therefore, we copy-paste kernel code here
 * so that we can call skb_splice_bits() from our module.
 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
#define NUM_PIPE_BUFFERS(p) (p)->buffers
#else
#define NUM_PIPE_BUFFERS(p) PIPE_BUFFERS
#define PIPE_DEF_BUFFERS PIPE_BUFFERS

/* The following functions are not exported in kernels < 2.6.35 */
/**
 * generic_pipe_buf_map - virtually map a pipe buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer that should be mapped
 * @atomic:	whether to use an atomic map
 *
 * Description:
 *	This function returns a kernel virtual address mapping for the
 *	pipe_buffer passed in @buf. If @atomic is set, an atomic map is provided
 *	and the caller has to be careful not to fault before calling
 *	the unmap function.
 *
 *	Note that this function occupies KM_USER0 if @atomic != 0.
 */
void *generic_pipe_buf_map(struct pipe_inode_info *pipe,
			   struct pipe_buffer *buf, int atomic)
{
	if (atomic) {
		buf->flags |= PIPE_BUF_FLAG_ATOMIC;
		return kmap_atomic(buf->page, KM_USER0);
	}

	return kmap(buf->page);
}

/**
 * generic_pipe_buf_unmap - unmap a previously mapped pipe buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer that should be unmapped
 * @map_data:	the data that the mapping function returned
 *
 * Description:
 *	This function undoes the mapping that ->map() provided.
 */
void generic_pipe_buf_unmap(struct pipe_inode_info *pipe,
			    struct pipe_buffer *buf, void *map_data)
{
	if (buf->flags & PIPE_BUF_FLAG_ATOMIC) {
		buf->flags &= ~PIPE_BUF_FLAG_ATOMIC;
		kunmap_atomic(map_data, KM_USER0);
	} else
		kunmap(buf->page);
}

int generic_pipe_buf_confirm(struct pipe_inode_info *info,
			     struct pipe_buffer *buf)
{
	return 0;
}

#endif /* LINUX_VERSION_CODE */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
static void pipe_lock_nested(struct pipe_inode_info *pipe, int subclass)
{
	if (pipe->inode)
		mutex_lock_nested(&pipe->inode->i_mutex, subclass);
}

void pipe_lock(struct pipe_inode_info *pipe)
{
	/*
	 * pipe_lock() nests non-pipe inode locks (for writing to a file)
	 */
	pipe_lock_nested(pipe, I_MUTEX_PARENT);
}

void pipe_unlock(struct pipe_inode_info *pipe)
{
	if (pipe->inode)
		mutex_unlock(&pipe->inode->i_mutex);
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))
#define skb_walk_frags(skb, iter)       \
        for (iter = skb_shinfo(skb)->frag_list; iter; iter = iter->next)
#endif

/* Drop the inode semaphore and wait for a pipe event, atomically */
void pipe_wait(struct pipe_inode_info *pipe)
{
	DEFINE_WAIT(wait);

	/*
	 * Pipes are system-local resources, so sleeping on them
	 * is considered a noninteractive wait:
	 */
	prepare_to_wait(&pipe->wait, &wait, TASK_INTERRUPTIBLE);
	pipe_unlock(pipe);
	schedule();
	finish_wait(&pipe->wait, &wait);
	pipe_lock(pipe);
}

/**
 * splice_to_pipe - fill passed data into a pipe
 * @pipe:	pipe to fill
 * @spd:	data to fill
 *
 * Description:
 *    @spd contains a map of pages and len/offset tuples, along with
 *    the struct pipe_buf_operations associated with these pages. This
 *    function will link that data to the pipe.
 *
 */

ssize_t splice_to_pipe(struct pipe_inode_info *pipe,
		       struct splice_pipe_desc *spd)
{
	unsigned int spd_pages = spd->nr_pages;
	int ret, do_wakeup, page_nr;

	ret = 0;
	do_wakeup = 0;
	page_nr = 0;

	pipe_lock(pipe);

	for (;;) {
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		if (pipe->nrbufs < NUM_PIPE_BUFFERS(pipe)) {
			int newbuf = (pipe->curbuf + pipe->nrbufs) & 
                                (NUM_PIPE_BUFFERS(pipe) - 1);
			struct pipe_buffer *buf = pipe->bufs + newbuf;

			buf->page = spd->pages[page_nr];
			buf->offset = spd->partial[page_nr].offset;
			buf->len = spd->partial[page_nr].len;
			buf->private = spd->partial[page_nr].private;
			buf->ops = spd->ops;
			if (spd->flags & SPLICE_F_GIFT)
				buf->flags |= PIPE_BUF_FLAG_GIFT;

			pipe->nrbufs++;
			page_nr++;
			ret += buf->len;

			if (pipe->inode)
				do_wakeup = 1;

			if (!--spd->nr_pages)
				break;
			if (pipe->nrbufs < NUM_PIPE_BUFFERS(pipe))
				continue;

			break;
		}

		if (spd->flags & SPLICE_F_NONBLOCK) {
			if (!ret)
				ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}

		if (do_wakeup) {
			smp_mb();
			if (waitqueue_active(&pipe->wait))
				wake_up_interruptible_sync(&pipe->wait);
			kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
			do_wakeup = 0;
		}

		pipe->waiting_writers++;
		pipe_wait(pipe);
		pipe->waiting_writers--;
	}

	pipe_unlock(pipe);

	if (do_wakeup) {
		smp_mb();
		if (waitqueue_active(&pipe->wait))
			wake_up_interruptible(&pipe->wait);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
	}

	while (page_nr < spd_pages) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
		page_cache_release(spd->pages[page_nr++]);
#else
                spd->spd_release(spd, page_nr++);
#endif
        }
	return ret;
}

/*
 * Check if we need to grow the arrays holding pages and partial page
 * descriptions.
 */

/* Hotfix for detecting Ubuntu 12.04 kernel, which seems to have
 * patches applied from later kernels */
#if UBUNTU_NON_STANDARD_KERNEL || \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,5))
#define CONST const
#else
#define CONST 
#endif
                
int splice_grow_spd(CONST struct pipe_inode_info *pipe, struct splice_pipe_desc *spd)
{
	if (NUM_PIPE_BUFFERS(pipe) <= PIPE_DEF_BUFFERS)
		return 0;
        
	spd->pages = kmalloc(NUM_PIPE_BUFFERS(pipe) * sizeof(struct page *), GFP_KERNEL);
	spd->partial = kmalloc(NUM_PIPE_BUFFERS(pipe) * sizeof(struct partial_page), GFP_KERNEL);
        
	if (spd->pages && spd->partial)
		return 0;
        
	kfree(spd->pages);
	kfree(spd->partial);
	return -ENOMEM;
}

#if UBUNTU_NON_STANDARD_KERNEL ||                       \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,5))
void splice_shrink_spd(struct splice_pipe_desc *spd)
{
        if (spd->nr_pages_max <= PIPE_DEF_BUFFERS)
                return;
        
	kfree(spd->pages);
	kfree(spd->partial);
}
#else
void splice_shrink_spd(struct pipe_inode_info *pipe,
                       struct splice_pipe_desc *spd)
{
        if (NUM_PIPE_BUFFERS(pipe) <= PIPE_DEF_BUFFERS)
		return;
        
	kfree(spd->pages);
	kfree(spd->partial);
}
#endif
 
static void sock_pipe_buf_release(struct pipe_inode_info *pipe,
                                  struct pipe_buffer *buf)
{
	put_page(buf->page);
}

static void sock_pipe_buf_get(struct pipe_inode_info *pipe,
				struct pipe_buffer *buf)
{
	get_page(buf->page);
}

static int sock_pipe_buf_steal(struct pipe_inode_info *pipe,
			       struct pipe_buffer *buf)
{
	return 1;
}


/* Pipe buffer operations for a socket. */
static const struct pipe_buf_operations sock_pipe_buf_ops = {
	.can_merge = 0,
	.map = generic_pipe_buf_map,
	.unmap = generic_pipe_buf_unmap,
	.confirm = generic_pipe_buf_confirm,
	.release = sock_pipe_buf_release,
	.steal = sock_pipe_buf_steal,
	.get = sock_pipe_buf_get,
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
static void sock_spd_release(struct splice_pipe_desc *spd, unsigned int i)
{
	put_page(spd->pages[i]);
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
static struct page *linear_to_page(struct page *page, unsigned int *len,
				   unsigned int *offset,
				   struct sock *sk)
{
	struct page_frag *pfrag = sk_page_frag(sk);

	if (!sk_page_frag_refill(sk, pfrag))
		return NULL;

	*len = min_t(unsigned int, *len, pfrag->size - pfrag->offset);

	memcpy(page_address(pfrag->page) + pfrag->offset,
	       page_address(page) + *offset, *len);
	*offset = pfrag->offset;
	pfrag->offset += *len;

	return pfrag->page;
}

static bool spd_can_coalesce(const struct splice_pipe_desc *spd,
			     struct page *page,
			     unsigned int offset)
{
	return	spd->nr_pages &&
		spd->pages[spd->nr_pages - 1] == page &&
		(spd->partial[spd->nr_pages - 1].offset +
		 spd->partial[spd->nr_pages - 1].len == offset);
}

/*
 * Fill page/offset/length into spd, if it can hold more pages.
 */
static bool spd_fill_page(struct splice_pipe_desc *spd,
			  struct pipe_inode_info *pipe, struct page *page,
			  unsigned int *len, unsigned int offset,
			  bool linear,
			  struct sock *sk)
{
	if (unlikely(spd->nr_pages == MAX_SKB_FRAGS))
		return true;

	if (linear) {
		page = linear_to_page(page, len, &offset, sk);
		if (!page)
			return true;
	}
	if (spd_can_coalesce(spd, page, offset)) {
		spd->partial[spd->nr_pages - 1].len += *len;
		return false;
	}
	get_page(page);
	spd->pages[spd->nr_pages] = page;
	spd->partial[spd->nr_pages].len = *len;
	spd->partial[spd->nr_pages].offset = offset;
	spd->nr_pages++;

	return false;
}

static bool __splice_segment(struct page *page, unsigned int poff,
			     unsigned int plen, unsigned int *off,
			     unsigned int *len,
			     struct splice_pipe_desc *spd, bool linear,
			     struct sock *sk,
			     struct pipe_inode_info *pipe)
{
	if (!*len)
		return true;

	/* skip this segment if already processed */
	if (*off >= plen) {
		*off -= plen;
		return false;
	}

	/* ignore any bits we already processed */
	poff += *off;
	plen -= *off;
	*off = 0;

	do {
		unsigned int flen = min(*len, plen);

		if (spd_fill_page(spd, pipe, page, &flen, poff,
				  linear, sk))
			return true;
		poff += flen;
		plen -= flen;
		*len -= flen;
	} while (*len && plen);

	return false;
}

static bool __skb_splice_bits(struct sk_buff *skb, struct pipe_inode_info *pipe,
			      unsigned int *offset, unsigned int *len,
			      struct splice_pipe_desc *spd, struct sock *sk)
{
	int seg;

	/* map the linear part :
	 * If skb->head_frag is set, this 'linear' part is backed by a
	 * fragment, and if the head is not shared with any clones then
	 * we can avoid a copy since we own the head portion of this page.
	 */
	if (__splice_segment(virt_to_page(skb->data),
			     (unsigned long) skb->data & (PAGE_SIZE - 1),
			     skb_headlen(skb),
			     offset, len, spd,
			     skb_head_is_locked(skb),
			     sk, pipe))
		return true;

	/*
	 * then map the fragments
	 */
	for (seg = 0; seg < skb_shinfo(skb)->nr_frags; seg++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[seg];

		if (__splice_segment(skb_frag_page(f),
				     f->page_offset, skb_frag_size(f),
				     offset, len, spd, false, sk, pipe))
			return true;
	}

	return false;
}

#else
static inline struct page *linear_to_page(struct page *page, unsigned int *len,
					  unsigned int *offset,
					  struct sk_buff *skb, struct sock *sk)
{
	struct page *p = sk->sk_sndmsg_page;
	unsigned int off;

	if (!p) {
new_page:
		p = sk->sk_sndmsg_page = alloc_pages(sk->sk_allocation, 0);
		if (!p)
			return NULL;

		off = sk->sk_sndmsg_off = 0;
		/* hold one ref to this page until it's full */
	} else {
		unsigned int mlen;

		off = sk->sk_sndmsg_off;
		mlen = PAGE_SIZE - off;
		if (mlen < 64 && mlen < *len) {
			put_page(p);
			goto new_page;
		}

		*len = min_t(unsigned int, *len, mlen);
	}

	memcpy(page_address(p) + off, page_address(page) + *offset, *len);
	sk->sk_sndmsg_off += *len;
	*offset = off;
	get_page(p);

	return p;
}

static inline int spd_fill_page(struct splice_pipe_desc *spd,
				struct pipe_inode_info *pipe, struct page *page,
				unsigned int *len, unsigned int offset,
				struct sk_buff *skb, int linear,
				struct sock *sk)
{
	if (unlikely(spd->nr_pages == NUM_PIPE_BUFFERS(pipe)))
		return 1;

	if (linear) {
		page = linear_to_page(page, len, &offset, skb, sk);
		if (!page)
			return 1;
	} else
		get_page(page);

	spd->pages[spd->nr_pages] = page;
	spd->partial[spd->nr_pages].len = *len;
	spd->partial[spd->nr_pages].offset = offset;
	spd->nr_pages++;

	return 0;
}
static inline void __segment_seek(struct page **page, unsigned int *poff,
				  unsigned int *plen, unsigned int off)
{
	unsigned long n;

	*poff += off;
	n = *poff / PAGE_SIZE;
	if (n)
		*page = nth_page(*page, n);

	*poff = *poff % PAGE_SIZE;
	*plen -= off;
}

static inline int __splice_segment(struct page *page, unsigned int poff,
				   unsigned int plen, unsigned int *off,
				   unsigned int *len, struct sk_buff *skb,
				   struct splice_pipe_desc *spd, int linear,
				   struct sock *sk,
				   struct pipe_inode_info *pipe)
{
	if (!*len)
		return 1;

	/* skip this segment if already processed */
	if (*off >= plen) {
		*off -= plen;
		return 0;
	}

	/* ignore any bits we already processed */
	if (*off) {
		__segment_seek(&page, &poff, &plen, *off);
		*off = 0;
	}

	do {
		unsigned int flen = min(*len, plen);

		/* the linear region may spread across several pages  */
		flen = min_t(unsigned int, flen, PAGE_SIZE - poff);

		if (spd_fill_page(spd, pipe, page, &flen, poff, skb, linear, sk))
			return 1;

		__segment_seek(&page, &poff, &plen, flen);
		*len -= flen;

	} while (*len && plen);

	return 0;
}


/*
 * Map linear and fragment data from the skb to spd. It reports failure if the
 * pipe is full or if we already spliced the requested length.
 */
static int __skb_splice_bits(struct sk_buff *skb, struct pipe_inode_info *pipe,
			     unsigned int *offset, unsigned int *len,
			     struct splice_pipe_desc *spd, struct sock *sk)
{
	int seg;

	/*
	 * map the linear part
	 */
	if (__splice_segment(virt_to_page(skb->data),
			     (unsigned long) skb->data & (PAGE_SIZE - 1),
			     skb_headlen(skb),
			     offset, len, skb, spd, 1, sk, pipe))
		return 1;

	/*
	 * then map the fragments
	 */
	for (seg = 0; seg < skb_shinfo(skb)->nr_frags; seg++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[seg];

		if (__splice_segment(skb_frag_page(f), 
                                     f->page_offset, skb_frag_size(f),
				     offset, len, skb, spd, 0, sk, pipe))
			return 1;
	}

	return 0;
}
#endif

/*
 * Map data from the skb to a pipe. Should handle both the linear part,
 * the fragments, and the frag list. It does NOT handle frag lists within
 * the frag list, if such a thing exists. We'd probably need to recurse to
 * handle that cleanly.
 */
int skb_splice_bits(struct sk_buff *skb, unsigned int offset,
		    struct pipe_inode_info *pipe, unsigned int tlen,
		    unsigned int flags)
{
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct page *pages[PIPE_DEF_BUFFERS];
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.flags = flags,
		.ops = &sock_pipe_buf_ops,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
		.spd_release = sock_spd_release,
#endif
	};
	struct sk_buff *frag_iter;
	struct sock *sk = skb->sk;
	int ret = 0;

	if (splice_grow_spd(pipe, &spd))
		return -ENOMEM;

	/*
	 * __skb_splice_bits() only fails if the output has no room left,
	 * so no point in going over the frag_list for the error case.
	 */
	if (__skb_splice_bits(skb, pipe, &offset, &tlen, &spd, sk))
		goto done;
	else if (!tlen)
		goto done;

	/*
	 * now see if we have a frag_list to map
	 */
	skb_walk_frags(skb, frag_iter) {
		if (!tlen)
			break;
		if (__skb_splice_bits(frag_iter, pipe, &offset, &tlen, &spd, sk))
			break;
	}

done:
	if (spd.nr_pages) {
		/*
		 * Drop the socket lock, otherwise we have reverse
		 * locking dependencies between sk_lock and i_mutex
		 * here as compared to sendfile(). We enter here
		 * with the socket lock held, and splice_to_pipe() will
		 * grab the pipe inode lock. For sendfile() emulation,
		 * we call into ->sendpage() with the i_mutex lock held
		 * and networking will grab the socket lock.
		 */
		release_sock(sk);
		ret = splice_to_pipe(pipe, &spd);
		lock_sock(sk);
	}

#if UBUNTU_NON_STANDARD_KERNEL ||                       \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,5))
        splice_shrink_spd(&spd);
#else
	splice_shrink_spd(pipe, &spd);
#endif
	return ret;
}

#endif /* ENABLE_SPLICE */
