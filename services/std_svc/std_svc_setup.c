/*
 * Copyright (c) 2014-2016, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <cpu_data.h>
#include <debug.h>
#include <pmf.h>
#include <psci.h>
#include <runtime_instr.h>
#include <runtime_svc.h>
#include <smcc_helpers.h>
#include <std_svc.h>
#include <stdint.h>
#include <uuid.h>

/* Standard Service UUID */
DEFINE_SVC_UUID(arm_svc_uid,
		0x108d905b, 0xf863, 0x47e8, 0xae, 0x2d,
		0xc0, 0xfb, 0x56, 0x41, 0xf6, 0xe2);

/* Setup Standard Services */
static int32_t std_svc_setup(void)
{
	uintptr_t svc_arg;

	svc_arg = get_arm_std_svc_args(PSCI_FID_MASK);
	assert(svc_arg);

	/*
	 * PSCI is the only specification implemented as a Standard Service.
	 * The `psci_setup()` also does EL3 architectural setup.
	 */
	return psci_setup((const psci_lib_args_t *)svc_arg);
}

/*
 * Top-level Standard Service SMC handler. This handler will in turn dispatch
 * calls to PSCI SMC handler
 */
uintptr_t std_svc_smc_handler(uint32_t smc_fid,
			     u_register_t x1,
			     u_register_t x2,
			     u_register_t x3,
			     u_register_t x4,
			     void *cookie,
			     void *handle,
			     u_register_t flags)
{
	/*
	 * Dispatch PSCI calls to PSCI SMC handler and return its return
	 * value
	 */
	if (is_psci_fid(smc_fid)) {
		uint64_t ret;

#if ENABLE_RUNTIME_INSTRUMENTATION

		/*
		 * Flush cache line so that even if CPU power down happens
		 * the timestamp update is reflected in memory.
		 */
		PMF_WRITE_TIMESTAMP(rt_instr_svc,
		    RT_INSTR_ENTER_PSCI,
		    PMF_CACHE_MAINT,
		    get_cpu_data(cpu_data_pmf_ts[CPU_DATA_PMF_TS0_IDX]));
#endif

		ret = psci_smc_handler(smc_fid, x1, x2, x3, x4,
		    cookie, handle, flags);

#if ENABLE_RUNTIME_INSTRUMENTATION
		PMF_CAPTURE_TIMESTAMP(rt_instr_svc,
		    RT_INSTR_EXIT_PSCI,
		    PMF_NO_CACHE_MAINT);
#endif

		SMC_RET1(handle, ret);
	}

	switch (smc_fid) {
	
	case ARM_STD_SVC_CALL_COUNT:
		/*
		 * Return the number of Standard Service Calls. PSCI is the only
		 * standard service implemented; so return number of PSCI calls
		 */
		SMC_RET1(handle, PSCI_NUM_CALLS);

	case ARM_STD_SVC_UID:
		/* Return UID to the caller */
		SMC_UUID_RET(handle, arm_svc_uid);

	case ARM_STD_SVC_VERSION:
		/* Return the version of current implementation */
		SMC_RET2(handle, STD_SVC_VERSION_MAJOR, STD_SVC_VERSION_MINOR);
	case MY_FUN_ID:
		tf_printf("smc_id : %x\n",smc_fid);
		SMC_RET0(handle);
	case DERIVE_KEY:
	{
		tf_printf("smcid 0x%x address 0x%x\n",smc_fid, (unsigned int)x1);
		int len = ((struct en_de*)x1)->len2;
		tf_printf("SMC:not die 1\n");
		signed char *de = ((struct en_de*)x1)->arg2;
		signed char *en = ((struct en_de*)x1)->arg1;
		tf_printf("SMC:not die 2\n");
		int i = 0;
		for (; i < len; ++i){
			en[i] = de[i];
		}
		tf_printf("SMC:DERIVE KEY FINISH\n");
		SMC_RET0(handle);
	}

	case ENCRYPT:{
		tf_printf("SMC:ENCRYPT smcid 0x%x address 0x%x\n",smc_fid, (unsigned int)x1);
		struct s *s1= (struct s*)x1;
		signed char *plain = s1->arg1;
		signed char *aes   = s1->arg2;
		signed char *encrypt = s1->arg3;
		do_en(plain, aes, encrypt, s1->len1, s1->len2);
		SMC_RET0(handle);		
	}
	
	case DECRYPT:{
		tf_printf("SMC:DECRYPT smcid 0x%x address 0x%x\n",smc_fid, (unsigned int)x1);
	
		struct s *s1= (struct s*)x1;
		signed char *encrypt = s1->arg1;
		signed char *aes   = s1->arg2;
		signed char *plain = s1->arg3;
		do_en(encrypt, aes, plain, s1->len1, s1->len2);
		SMC_RET0(handle);		
	}
	default:
		WARN("Unimplemented Standard Service Call: 0x%x \n", smc_fid);
		SMC_RET1(handle, SMC_UNK);
	}
}

void do_en(signed char *src_data, signed char *aes, signed char *dst_data, unsigned int len, unsigned int aes_len)
{
	int i = 0;
	for (; i<len ;++i){
		dst_data[i] = src_data[i]^aes[i%aes_len];
	}
} 
/* Register Standard Service Calls as runtime service */
DECLARE_RT_SVC(
		std_svc,

		OEN_STD_START,
		OEN_STD_END,
		SMC_TYPE_FAST,
		std_svc_setup,
		std_svc_smc_handler
);
