#if defined(__KERNEL__) && defined(__linux__)
#include <linux/hash.h>

static inline unsigned int
full_bitstring_hash(const void *bits_in, unsigned int num_bits)
{
	const unsigned char *bits = (const unsigned char *)bits_in;
	unsigned int len = num_bits / 8;
	unsigned long hash = init_name_hash();
	
	/* Compute the number of bits in the last byte to hash */
	num_bits -= (len * 8);

	/* Hash up to the last byte. */
	while (len--)
		hash = partial_name_hash(*bits++, hash);
	
	/* Hash the bits of the last byte if necessary */
	if (num_bits) {
		/* We need to mask off the last bits to use and hash those */
		unsigned char last_bits = (0xff << (8 - num_bits)) & *bits;
		partial_name_hash(last_bits, hash);
	}
	return end_name_hash(hash);
}

#else
#include <common/hash.h>
#endif
