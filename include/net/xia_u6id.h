#ifndef _NET_XIA_U6ID_H
#define _NET_XIA_U6ID_H

#ifndef __KERNEL__
#include <stdbool.h>
#endif

#define XIDTYPE_U6ID            (__cpu_to_be32(0x1b))

struct local_u6id_info {
	bool	tunnel;
	bool	no_check;
};

#endif	/* _NET_XIA_U6ID_H */
