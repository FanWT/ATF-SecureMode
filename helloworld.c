#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vtz");

#define DERIVE_KEY_CMD 0
#define ENCRYPT 1
/*2 is reserved by linux kernel*/
#define DECRYPT 3

#define DERIVE_KEY_SMCID		0x8400ff05
#define ENCRYPT_SMCID			0X8400ff06
#define DECRYPT_SMCID			0X8400ff07
struct en_de{
    signed char *encrypt_data;
    unsigned int encrypt_len;
    signed char *decrypt_data;
    unsigned int decrypt_len;
};

struct s{
	signed char *arg1;
	unsigned int len1;
	signed char *arg2;
	unsigned int len2;
	signed char *arg3;
	unsigned int len3;
};
static int major;

static long sgxdev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
	uint32_t smc_id;
	void *de_buffer,*en_buffer;
	int ret;
	printk("KERNEL:cmd = %d\n",cmd);
	switch (cmd) {
		case DERIVE_KEY_CMD:{//derive key
			printk("KERNEL:handling derive key method\n");
			smc_id = DERIVE_KEY_SMCID;
			struct en_de args;
			
			if ((ret = copy_from_user(&args,(struct en_de *)arg,sizeof(struct en_de)))!=0)
				return -EFAULT;
			de_buffer = kmalloc(args.decrypt_len, GFP_KERNEL);
			en_buffer = kmalloc(args.encrypt_len, GFP_KERNEL);//flag perhaps needs to be modified
			if ((ret = copy_from_user(de_buffer, args.decrypt_data, args.decrypt_len)) != 0)
				return -EFAULT;
			args.encrypt_data = virt_to_phys(en_buffer);
			args.decrypt_data = virt_to_phys(de_buffer);
			unsigned long phy_add = virt_to_phys(&args);
		//	printk("KERNEL:phy_add 0x%x\n",phy_add);
			__asm__("mov x0,%0\n\t"
				"mov x1,%1\n\t"
				"smc #0"
				:
				:"r"(smc_id),"r"(phy_add)
				:"x0","x1");
			if ((ret = copy_from_user(&args,(struct en_de *)arg,sizeof(struct en_de)))!=0)
				return -EFAULT;

			copy_to_user(args.encrypt_data,en_buffer,args.encrypt_len);
			return 0;
		}
		case ENCRYPT:{
			printk("KERNEL:handling encrypt method\n");
			smc_id = ENCRYPT_SMCID;
			struct s args;
				
			if ((ret = copy_from_user(&args,(struct s*)arg,sizeof(struct s)))!=0)
				return -EFAULT;
			void *plain_buffer = kmalloc(args.len1, GFP_KERNEL);
			void *aes_key = kmalloc(args.len2, GFP_KERNEL);//flag perhaps needs to be modified
			void *encrypt_buffer = kmalloc(args.len3, GFP_KERNEL);
			printk("KERNEL:ENCRYPT not die 1\n");
			if ((ret = copy_from_user(plain_buffer, args.arg1, args.len1)) != 0)
				return -EFAULT;
			if ((ret = copy_from_user(aes_key, args.arg2, args.len2))!=0)
				return -EFAULT;
			args.arg1 = virt_to_phys(plain_buffer);
			args.arg2 = virt_to_phys(aes_key);
			args.arg3 = virt_to_phys(encrypt_buffer);
			printk("KERNEL:ENCRYPT not die 2\n");
			unsigned long phy_add = virt_to_phys(&args);
			__asm__("mov x0,%0\n\t"
				"mov x1,%1\n\t"
				"smc #0"
				:
				:"r"(smc_id),"r"(phy_add)
				:"x0","x1");
			copy_from_user(&args,(struct s*)arg,sizeof(struct s));
			copy_to_user(args.arg3,encrypt_buffer,args.len3);
			return 0;

		}
		case DECRYPT:{
			printk("KERNEL:handling decrypt method\n");
			smc_id = DECRYPT_SMCID;
			struct s args;
			
			if ((ret = copy_from_user(&args,(struct s*)arg,sizeof(struct s)))!=0)
				return -EFAULT;
			void *plain_buffer = kmalloc(args.len3, GFP_KERNEL);
			void *aes_key = kmalloc(args.len2, GFP_KERNEL);//flag perhaps needs to be modified
			void *encrypt_buffer = kmalloc(args.len1, GFP_KERNEL);
			if ((ret = copy_from_user(encrypt_buffer, args.arg1, args.len1)) != 0)
				return -EFAULT;
			if ((ret = copy_from_user(aes_key, args.arg2, args.len2))!=0)
				return -EFAULT;
			args.arg3 = virt_to_phys(plain_buffer);
			args.arg2 = virt_to_phys(aes_key);
			args.arg1 = virt_to_phys(encrypt_buffer);
			unsigned long phy_add = virt_to_phys(&args);
			__asm__("mov x0,%0\n\t"
				"mov x1,%1\n\t"
				"smc #0"
				:
				:"r"(smc_id),"r"(phy_add)
				:"x0","x1");
			copy_from_user(&args,(struct s*)arg,sizeof(struct s));
			copy_to_user(args.arg3,plain_buffer,args.len3);
			return 0;

		}
		case 10:
		{
			uint32_t smc_id = 0x8400ff04;
			printk("hello from kernel module\n");
			return 0;
		}
		default:
			printk("default case\n");

	}
	return 1;
}

// ===module glue===


static struct file_operations fops = {
	.unlocked_ioctl = sgxdev_ioctl,
};

static int __init vtz_module_init(void) {

	volatile int i,m;
	
	
	major = register_chrdev(0, "vtzdev", &fops);
	if (major < 0) {
		printk ("[vtz] Registering the character device failed with %d\n", major);
		return major;
	}
	printk("[vtz] create node with: sudo mknod -m 666 /dev/vtz c %d 0\n", major);
	return 0;
}

static void __exit vtz_module_exit(void) {
	unregister_chrdev(major, "vtzdev");
	printk("[vtz] unloaded\n");
}

module_init(vtz_module_init);
module_exit(vtz_module_exit);
