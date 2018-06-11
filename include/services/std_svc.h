/*
 * Copyright (c) 2014-2016, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __STD_SVC_H__
#define __STD_SVC_H__

/* SMC function IDs for Standard Service queries */

#define ARM_STD_SVC_CALL_COUNT		0x8400ff00
#define ARM_STD_SVC_UID			0x8400ff01
/*					0x8400ff02 is reserved */
#define ARM_STD_SVC_VERSION		0x8400ff03

#define MY_FUN_ID			0x8400ff04
#define DERIVE_KEY			0X8400ff05
#define ENCRYPT				0X8400ff06
#define DECRYPT				0X8400ff07
/* ARM Standard Service Calls version numbers */
#define STD_SVC_VERSION_MAJOR		0x0
#define STD_SVC_VERSION_MINOR		0x1

struct en_de {
	signed char *arg1;//en
	unsigned int len1;
	signed char *arg2;//de
	unsigned int len2;
};
struct s {
	signed char *arg1;
	unsigned int len1;
	signed char *arg2;
	unsigned int len2;
	signed char *arg3;
	unsigned int len3;
};
/*
 * Get the ARM Standard Service argument from EL3 Runtime.
 * This function must be implemented by EL3 Runtime and the
 * `svc_mask` identifies the service. `svc_mask` is a bit
 * mask identifying the range of SMC function IDs available
 * to the service.
 */
uintptr_t get_arm_std_svc_args(unsigned int svc_mask);
void do_en(signed char*, signed char*, signed char*, unsigned int, unsigned int);
//aes algorithm usage

#define SUCCESS 0
#define PARM_ERROR 1
#define NOT_INIT_KEY 2

#define BLOCK_SIZE 16

typedef struct
{
	uint32_t nr;		// rounds
	uint32_t *rk;		// round_key
	uint32_t buf[68];	// store round_keys, each block is 4 bytes
} aes_context;

int aes_set_key(aes_context *ctx, const uint8_t *key, uint32_t key_bit);

int aes_encrypt_block(aes_context *ctx, uint8_t cipher_text[16], const uint8_t text[16]);
int aes_decrypt_block(aes_context *ctx, uint8_t text[16], const uint8_t cipher_text[16]);

void *memcpy1(void *dest, const void *src, size_t count)  
{  
	char *d;  
	const char *s;  
   
	if ((dest > (src+count)) || (dest < src))  
    {  
		d = dest;  
	    s = src;  
	    while (count--)  
	        *d++ = *s++;          
    }  
	else /* overlap */  
    {  
	    d = (char *)(dest + count - 1); /* offset of pointer is from 0 */  
	    s = (char *)(src + count -1);  
	    while (count --)  
	        *d-- = *s--;  
    }  
    
	return dest;  
}  
#endif /* __STD_SVC_H__ */
