/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_H
#define _SERVAL_H

#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/in.h>

#define SERVAL_ASSERT(predicate) __ASSERT__(predicate, __LINE__)

#define __PASTE__(a,b) a##b
#define __ASSERT__(predicate,line)                                 \
        typedef char __PASTE__(assertion_failed_,line)[2*!!(predicate)-1];

#define AF_SERVAL 28
#define PF_SERVAL AF_SERVAL   /* include/linux/socket.h */

#define SERVAL_PROTO_TCP 6
#define SERVAL_PROTO_UDP 17

/* Ethernet protocol number */
#define ETH_P_SERVAL 0x0809

/* IP Protocol number */
#define IPPROTO_SERVAL 144

struct service_id {
        union { 
                struct {
                        uint8_t un_ss[4];
                        uint8_t un_local[4];
                        uint8_t un_group[4];
                        uint8_t un_selfcert[20];
                };
                uint8_t	 un_id8[32];
                uint16_t un_id16[16];
                uint32_t un_id32[8];
        } srv_un;
#define s_ss srv_un.un_ss;
#define s_local srv_un.un_local;
#define s_group srv_un.un_group;
#define s_sfc srv_un.un_selfcert;
#define s_sid srv_un.un_id8
#define s_sid16 srv_un.un_id16
#define s_sid32 srv_un.un_id32
};

SERVAL_ASSERT(sizeof(struct service_id) == 32)

#define SERVICE_ID_MAX_PREFIX_BITS ((unsigned)(sizeof(struct service_id)<<3))

static inline struct service_id *service_id_copy(struct service_id *s1,
                                                 struct service_id *s2)
{
        return (struct service_id *)memcpy(s1, s2, sizeof(*s1));
}

enum sv_service_flags {
        /* bottom 2 bits reserved for scope - resolution and
         * registration */
        SVSF_HOST_SCOPE = 0,
        SVSF_LOCAL_SCOPE = 1,
        SVSF_DOMAIN_SCOPE = 2,
        SVSF_GLOBAL_SCOPE = 3,
        SVSF_STRICT_SCOPE = 1 << 3, /* interpret scope strictly, by
                                     * default, scopes are
                                     * inclusive */
        SVSF_ANYCAST = 1 << 4, /* service instance can be anycasted, 0
                                * = backup or strict match */
        SVSF_MULTICAST = 1 << 5, /* service instance can be
                                  * multicasted */
        SVSF_INVALID = 0xFF
};

struct sockaddr_sv {
#if defined(HAS_SOCKADDR_LEN)
        uint8_t sv_len;
#endif
        sa_family_t sv_family;
        uint8_t sv_flags;
        uint8_t sv_prefix_bits;
        struct service_id sv_srvid;
};

SERVAL_ASSERT(sizeof(struct sockaddr_sv) == 36)

#define SERVAL_ADDRSTRLEN 80

struct flow_id {
        union {
                uint8_t  un_id8[4];
                uint16_t un_id16[2];
                uint32_t un_id32;
        } fl_un;
#define s_id8  fl_un.un_id8
#define s_id16 fl_un.un_id16
#define s_id32 fl_un.un_id32
};

SERVAL_ASSERT(sizeof(struct flow_id) == 4)

struct net_addr {
        union {
                /* IPv6 address too big to fit in serval_skb_cb
                   together with 256-bit service_id atm. */
                /* struct in6_addr net_ip6; */
                struct in_addr un_ip;
                uint8_t un_raw[4];
        } net_un;
#define net_ip net_un.un_ip
#define net_raw net_un.un_raw
};

/**
 * Convert an ASCII character (char) to a byte integer. Returns -1 on
 * error.
 */
static inline int hextobyte(const char c)
{
        int value = -1;
        
        if (c >= '0' && c <= '9') {
                value = (c - '0');
        } else {
                char d = c | 0x20;
                
                if (d >= 'a' && d <= 'f')
                        value = d - 'a' + 10;
        }
        return value;
}

/**
 * Convert a hexadecimal string to a byte array. Returns 1 on success,
 * and 0 if the source string is not a valid hexadecimal string.
 */
static inline int serval_hexton(const char *src,
                                size_t src_len,
                                void *dst,
                                size_t dst_len)
{
        unsigned char *ptr = (unsigned char *)dst;

        while (*src != '\0' && dst_len-- && src_len--) {
                int value = hextobyte(*src++);

                if (value == -1)
                        return 0;
                
                value *= 16;
                        
                if (*src != '\0' && src_len--) {
                        int ret = hextobyte(*src++);

                        if (ret == -1)
                                return 0;
                        
                        value += ret;
                }
                *ptr++ = value;
        }
        
        return 1;
}

/*
 * Convert a byte array to a hexadecimal string. Will always
 * null-terminate.
 */
static inline char *serval_ntohex(const void *src,
                                  size_t src_len,
                                  char *dst,
                                  size_t dst_len)
{
        static const char hex[] = "0123456789abcdef";
        char *dst_ptr = (char *)dst;
        const unsigned char *src_ptr = (const unsigned char *)src;

        while (src_len && dst_len > 1) {
                *dst_ptr++ = hex[*src_ptr >> 4];

                if (--dst_len > 1) {
                        *dst_ptr++ = hex[*src_ptr++ & 0xf];
                        dst_len--;
                }
                src_len--;
        }
        
        if (dst_len)
                *dst_ptr = '\0';

        return dst;
}

static inline const char *service_id_to_str(const struct service_id *srvid)
{
        static char str[65*2];
        static int i = 0;
        i = (i + 1) % 2;
        return serval_ntohex(srvid, sizeof(*srvid),
                             &str[i*sizeof(str)/2], sizeof(str)/2);
}

static inline const char *flow_id_to_str(const struct flow_id *flowid)
{
        static char str[22];
        static int i = 0;
        i = (i + 1) % 2;
        snprintf(&str[i*sizeof(str)/2], sizeof(str)/2, 
                 "%u", ntohl(flowid->s_id32));
        return &str[i*sizeof(str)/2];
}

/**
 * Converts a binary service ID to string presentation
 * format. Equivalent to inet_ntop().
 */
static inline const char *serval_ntop(const void *src, char *dst, size_t len)
{
        return serval_ntohex(src, sizeof(struct service_id), dst, len);
}

/**
 * Converts a string in presentation format to a binary service
 * ID. Equivalent to inet_pton().
 */
static inline int serval_pton(const char *src, void *dst)
{
        return serval_hexton(src, 64, dst, sizeof(struct service_id));
}

struct sal_hdr {
        struct flow_id src_flowid;
        struct flow_id dst_flowid;
        uint8_t  shl; /* SAL Header Length (in number of 32-bit words) */
        uint8_t  protocol;
        uint16_t check;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_hdr) == 12)

#define SAL_HEADER_LEN                          \
        sizeof(struct sal_hdr)

/* Generic extension header */
struct sal_ext {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res:4,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	type:4,
                res:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t length;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_ext) == 2)

/*
  These defines can be used for convenient access to the fields in the
  base extension in extensions below. */
#define ext_type exthdr.type
#define ext_length exthdr.length

#define SAL_EXT_FIRST(sh) \
        ((struct sal_ext *)((char *)sh + SAL_HEADER_LEN))

#define SAL_EXT_NEXT(ext)                                               \
        ((struct sal_ext *)((ext->type == SAL_PAD_EXT ?                 \
                             (char *)ext + 1 :                          \
                             (char *)ext + ext->length)))

#define SAL_EXT_LEN(ext)                                \
        (ext->type == SAL_PAD_EXT ?                     \
         sizeof(struct sal_pad_ext) : ext->length)

enum sal_ext_type {
        SAL_PAD_EXT = 0,
        SAL_CONTROL_EXT = 1,
        SAL_SERVICE_EXT,
        SAL_ADDRESS_EXT,
        SAL_SOURCE_EXT,
        __SAL_EXT_TYPE_MAX,
};

struct sal_pad_ext {
        uint8_t pad[1];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_pad_ext) == 1);

#define SAL_NONCE_SIZE 8

struct sal_control_ext {
        struct sal_ext exthdr;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res1:2,
                fin:1,
                rst:1,
                nack:1,
                ack:1,
                rsyn:1,
		syn:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	syn:1,
                rsyn:1,
  		ack:1,
                nack:1,
                rst:1,
                fin:1,
                res1:2;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t  res2;
        uint32_t verno;
        uint32_t ackno;
        uint8_t  nonce[SAL_NONCE_SIZE];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_control_ext) == 20)

#define SAL_CONTROL_EXT_LEN                     \
        sizeof(struct sal_control_ext)

struct sal_service_ext {
        struct sal_ext exthdr;
        uint16_t res;
        struct service_id srvid;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_service_ext) == 36)

#define SAL_SERVICE_EXT_LEN                     \
        sizeof(struct sal_service_ext)

struct sal_address_ext {
        struct sal_ext exthdr;
        uint16_t res;
        uint32_t verno;
        uint32_t ackno;
        struct net_addr addrs[0];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_address_ext) == 12)

#define SAL_ADDRESS_EXT_LEN                     \
        sizeof(struct sal_address_ext)

struct sal_source_ext {
        struct sal_ext exthdr;
        uint16_t res;
        uint8_t source[0];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_source_ext) == 4)

#define SAL_SOURCE_EXT_MIN_LEN                  \
        (sizeof(struct sal_source_ext) + 4)

#define SAL_SOURCE_EXT_MAX_LEN                          \
        (sizeof(struct sal_source_ext) + (20 * 4))

#define __SAL_SOURCE_EXT_LEN(sz)             \
        (sz + sizeof(struct sal_source_ext))

#define SAL_SOURCE_EXT_LEN __SAL_SOURCE_EXT_LEN(4)

#define SAL_SOURCE_EXT_NUM_ADDRS(ext)                                \
        (((ext)->ext_length - sizeof(struct sal_source_ext)) / 4) 

#define SAL_SOURCE_EXT_GET_ADDR(ext, n)      \
        (&(ext)->source[n*4])

#define SAL_SOURCE_EXT_GET_LAST_ADDR(ext)                            \
        (&(ext)->source[(SAL_SOURCE_EXT_NUM_ADDRS(ext)-1)*4])

#endif /* _SERVAL_H */
