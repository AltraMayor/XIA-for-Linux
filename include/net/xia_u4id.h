#ifndef _NET_XIA_U4ID_H
#define _NET_XIA_U4ID_H

#ifndef __KERNEL__
#include <stdbool.h>
#endif

#define XIDTYPE_U4ID            (__cpu_to_be32(0x16))

struct local_u4id_info {
	bool	tunnel;
	bool	no_check;
};

#endif	/* _NET_XIA_U4ID_H */
