#ifndef _LINUX_XIA_H
#define _LINUX_XIA_H

/* XIP protocols. */
enum {
  XIPPROTO_XIP = 0,		/* eXpressive Internet Protocol		*/
  XIPPROTO_RAW = 255,		/* Raw XIP packets			*/
  XIPPROTO_MAX
};

#endif	/* _LINUX_XIA_H */
