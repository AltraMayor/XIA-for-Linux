/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LOG_H_
#define _LOG_H_

#include <debug.h>

/* Close the log.  Currently a NOP. */
#define LOG_ACTION_CLOSE          0
/* Open the log. Currently a NOP. */
#define LOG_ACTION_OPEN           1
/* Read from the log. */
#define LOG_ACTION_READ           2
/* Return number of unread characters in the log buffer */
#define LOG_ACTION_SIZE_UNREAD    3
/* Return size of the log buffer */
#define LOG_ACTION_SIZE_BUFFER    4

#define LOG_FROM_CALL 0
#define LOG_FROM_FILE 1

int do_log(int action, char *buf, size_t count, int from_file);
int log_vprintk(const char *levelstr, const char *func,
		const char *fmt, va_list args);

#endif /* _LOG_H_ */
